import 'dotenv/config';

import express from 'express';
import cors from 'cors';
import http from 'http';
import jwt from 'jsonwebtoken';
import WebSocket, { WebSocketServer } from 'ws';

const app = express();

const PORT = Number(process.env.PORT) || 9877;
const SECRET = process.env.REMOTE_CONTROL_SECRET;

if (!SECRET) {
  throw new Error('REMOTE_CONTROL_SECRET is missing');
}

/**
 * Example Render value:
 *
 * ALLOWED_ORIGINS=https://dynamic-gumdrop-f930bf.netlify.app,http://localhost:5173
 */
const allowedOrigins = new Set(
  (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean)
);

if (allowedOrigins.size === 0) {
  console.warn(
    '[Security] ALLOWED_ORIGINS is empty. Browser requests will be rejected.'
  );
}

app.use(
  cors({
    origin: (origin, callback) => {
      /**
       * Requests without Origin are normally server-to-server,
       * health checks, curl, Render checks, etc.
       */
      if (!origin) {
        return callback(null, true);
      }

      if (allowedOrigins.has(origin)) {
        return callback(null, true);
      }

      console.warn('[CORS] Blocked origin:', origin);

      return callback(
        new Error(`Origin not allowed: ${origin}`)
      );
    },

    methods: ['GET', 'POST', 'OPTIONS'],

    allowedHeaders: [
      'Content-Type',
      'Authorization',
    ],
  })
);

app.use(
  express.json({
    limit: '100kb',
  })
);

type ControllerRole =
  | 'officer'
  | 'advisor';

type ConnectionType =
  | 'target'
  | 'controller';

type TokenPayload = {
  type: ConnectionType;

  remoteSessionId: string;

  meetingId: string;

  userId: string;

  role?: ControllerRole;
};

type BrowserTarget = {
  tabId: string;
  tabName: string;
  url: string;
  socket: WebSocket;
};

type RelaySession = {
  remoteSessionId: string;

  meetingId: string;

  customerId: string;

  controllerId: string;

  controllerRole: ControllerRole;

  targets: Map<string, BrowserTarget>;

  activeTargetTabId?: string;

  controller?: WebSocket;

  createdAt: number;

  lastActivity: number;
};

const sessions =
  new Map<string, RelaySession>();

function createToken(
  payload: TokenPayload
): string {
  return jwt.sign(
    payload,
    SECRET!,
    {
      expiresIn: '10m',
    }
  );
}

function verifyToken(
  token: string
): TokenPayload {
  return jwt.verify(
    token,
    SECRET!
  ) as TokenPayload;
}

function safeSend(
  socket: WebSocket | undefined,
  data: unknown
) {
  if (
    !socket ||
    socket.readyState !== WebSocket.OPEN
  ) {
    return;
  }

  try {
    socket.send(
      JSON.stringify(data)
    );
  } catch (error) {
    console.error(
      '[Relay] Send failed:',
      error
    );
  }
}

function closeSocketSafely(
  socket: WebSocket | undefined,
  reason: string
) {
  if (!socket) {
    return;
  }

  try {
    if (
      socket.readyState === WebSocket.OPEN ||
      socket.readyState === WebSocket.CONNECTING
    ) {
      socket.close(
        1000,
        reason.substring(0, 120)
      );
    }
  } catch {
    // Ignore cleanup errors.
  }
}

function closeSession(
  remoteSessionId: string,
  reason: string
) {
  const session =
    sessions.get(
      remoteSessionId
    );

  if (!session) {
    return;
  }

  /**
   * Delete first so close events do not
   * recursively try to close the session.
   */
  sessions.delete(
    remoteSessionId
  );

  const stoppedMessage = {
    type: 'CONTROL_STOPPED',

    remoteSessionId,

    reason,
  };

  for (const target of session.targets.values()) {
    safeSend(
      target.socket,
      stoppedMessage
    );
  }

  safeSend(
    session.controller,
    stoppedMessage
  );

  for (const target of session.targets.values()) {
    closeSocketSafely(
      target.socket,
      reason
    );
  }

  closeSocketSafely(
    session.controller,
    reason
  );

  console.log(
    '[Relay] Session closed:',
    remoteSessionId,
    reason
  );
}

/**
 * ------------------------------------------------------------
 * HEALTH
 * ------------------------------------------------------------
 */
app.get(
  '/health',
  (_req, res) => {
    res.json({
      success: true,

      service:
        'remote-control-relay',

      mode:
        'browser-only',

      activeSessions:
        sessions.size,

      activeTargets:
        [...sessions.values()].reduce(
          (total, session) =>
            total + session.targets.size,
          0
        ),

      allowedOrigins:
        allowedOrigins.size,

      timestamp:
        new Date().toISOString(),
    });
  }
);

/**
 * ------------------------------------------------------------
 * AUTHORIZE REMOTE CONTROL
 * ------------------------------------------------------------
 *
 * Customer approval causes this endpoint to create:
 *
 * - targetToken       -> Customer Browser
 * - controllerToken   -> Advisor / Officer Browser
 *
 * IMPORTANT:
 * This is sufficient for your current development/testing flow.
 * Before handling sensitive production consultations, ideally
 * call this from your authenticated application backend rather
 * than allowing arbitrary public callers to create sessions.
 */
app.post(
  '/remote-control/authorize',

  (req, res) => {
    try {
      const {
        remoteSessionId,
        meetingId,
        customerId,
        controllerId,
        controllerRole,
      } = req.body ?? {};

      if (
        typeof remoteSessionId !== 'string' ||
        !remoteSessionId.trim()
      ) {
        return res
          .status(400)
          .json({
            success: false,

            message:
              'remoteSessionId is required',
          });
      }

      if (
        typeof meetingId !== 'string' ||
        !meetingId.trim()
      ) {
        return res
          .status(400)
          .json({
            success: false,

            message:
              'meetingId is required',
          });
      }

      if (
        typeof customerId !== 'string' ||
        !customerId.trim()
      ) {
        return res
          .status(400)
          .json({
            success: false,

            message:
              'customerId is required',
          });
      }

      if (
        typeof controllerId !== 'string' ||
        !controllerId.trim()
      ) {
        return res
          .status(400)
          .json({
            success: false,

            message:
              'controllerId is required',
          });
      }

      if (
        controllerRole !== 'advisor' &&
        controllerRole !== 'officer'
      ) {
        return res
          .status(403)
          .json({
            success: false,

            message:
              'Controller role must be advisor or officer',
          });
      }

      const normalizedSessionId =
        remoteSessionId.trim();

      /**
       * If this session ID already exists,
       * terminate the previous one.
       */
      if (
        sessions.has(
          normalizedSessionId
        )
      ) {
        closeSession(
          normalizedSessionId,
          'session_reauthorized'
        );
      }

      const session:
        RelaySession =
      {
        remoteSessionId:
          normalizedSessionId,

        meetingId:
          meetingId.trim(),

        customerId:
          customerId.trim(),

        controllerId:
          controllerId.trim(),

        controllerRole,

        targets:
          new Map<string, BrowserTarget>(),

        createdAt:
          Date.now(),

        lastActivity:
          Date.now(),
      };

      sessions.set(
        session.remoteSessionId,
        session
      );

      /**
       * Customer browser token
       */
      const targetToken =
        createToken({
          type:
            'target',

          remoteSessionId:
            session.remoteSessionId,

          meetingId:
            session.meetingId,

          userId:
            session.customerId,
        });

      /**
       * Advisor / Officer token
       */
      const controllerToken =
        createToken({
          type:
            'controller',

          remoteSessionId:
            session.remoteSessionId,

          meetingId:
            session.meetingId,

          userId:
            session.controllerId,

          role:
            session.controllerRole,
        });

      console.log(
        '[Relay] Browser session authorized:',
        session.remoteSessionId
      );

      return res.json({
        success: true,

        remoteSessionId:
          session.remoteSessionId,

        targetToken,

        controllerToken,

        expiresInMs:
          10 * 60 * 1000,
      });
    } catch (error) {
      console.error(
        '[Authorize]',
        error
      );

      return res
        .status(500)
        .json({
          success: false,

          message:
            'Remote control authorization failed',
        });
    }
  }
);

/**
 * ------------------------------------------------------------
 * HTTP SERVER
 * ------------------------------------------------------------
 */
const server =
  http.createServer(app);

/**
 * ------------------------------------------------------------
 * WEBSOCKET SERVER
 * ------------------------------------------------------------
 *
 * CORS middleware does NOT protect WebSockets.
 *
 * Therefore verify the browser Origin before
 * accepting a WebSocket connection.
 */
const wss =
  new WebSocketServer({
    server,

    path:
      '/remote-control',

    verifyClient: (
      info,
      done
    ) => {
      const origin =
        info.origin ||
        info.req.headers.origin;

      if (!origin) {
        console.warn(
          '[WebSocket] Rejected connection without Origin'
        );

        return done(
          false,
          403,
          'Origin required'
        );
      }

      if (
        !allowedOrigins.has(
          origin
        )
      ) {
        console.warn(
          '[WebSocket] Blocked origin:',
          origin
        );

        return done(
          false,
          403,
          'Origin not allowed'
        );
      }

      done(true);
    },
  });

/**
 * Browser-only input events.
 *
 * These events NEVER reach Windows.
 *
 * Customer React/browser receives them
 * and applies them to DOM elements.
 */
const allowedEvents =
  new Set([
    'MOUSE_MOVE',

    'MOUSE_CLICK',

    'MOUSE_DOUBLE_CLICK',

    'SCROLL',

    'KEY_DOWN',

    'KEY_UP',
  ]);

const allowedControllerCommands =
  new Set([
    'FOCUS_TAB',
    'NAVIGATE_TAB',
    'CLOSE_TAB',
  ]);

wss.on(
  'connection',

  (
    socket,
    request
  ) => {
    console.log(
      '[Relay] WebSocket connected:',
      request.headers.origin ||
        'unknown-origin'
    );

    let boundSession:
      RelaySession | null =
      null;

    let connectionType:
      ConnectionType | null =
      null;

    socket.on(
      'message',

      (raw) => {
        try {
          const parsed =
            JSON.parse(
              raw.toString()
            );

          /**
           * --------------------------------------------------
           * CUSTOMER BROWSER REGISTER
           * --------------------------------------------------
           */
          if (
            parsed.type ===
            'TARGET_REGISTER'
          ) {
            if (
              typeof parsed.token !==
              'string'
            ) {
              throw new Error(
                'Target token missing'
              );
            }

            const payload =
              verifyToken(
                parsed.token
              );

            if (
              payload.type !==
              'target'
            ) {
              throw new Error(
                'Invalid target token'
              );
            }

            if (
              payload.remoteSessionId !==
              parsed.remoteSessionId
            ) {
              throw new Error(
                'Target session mismatch'
              );
            }

            const session =
              sessions.get(
                parsed.remoteSessionId
              );

            if (!session) {
              throw new Error(
                'Remote session not found'
              );
            }

            if (
              payload.meetingId !==
              session.meetingId
            ) {
              throw new Error(
                'Meeting mismatch'
              );
            }

            if (
              payload.userId !==
              session.customerId
            ) {
              throw new Error(
                'Customer mismatch'
              );
            }

            const tabId =
              typeof parsed.tabId === 'string' &&
              parsed.tabId.trim()
                ? parsed.tabId.trim()
                : 'primary';

            const tabName =
              typeof parsed.tabName === 'string' &&
              parsed.tabName.trim()
                ? parsed.tabName.trim()
                : tabId === 'primary'
                  ? 'Primary'
                  : 'Customer Tab';

            const url =
              typeof parsed.url === 'string'
                ? parsed.url.slice(0, 2048)
                : '';

            const previousTarget =
              session.targets.get(
                tabId
              );

            if (
              previousTarget &&
              previousTarget.socket !== socket
            ) {
              closeSocketSafely(
                previousTarget.socket,
                'target_tab_replaced'
              );
            }

            session.targets.set(
              tabId,
              {
                tabId,
                tabName,
                url,
                socket,
              }
            );

            if (!session.activeTargetTabId) {
              session.activeTargetTabId =
                tabId;
            }

            session.lastActivity =
              Date.now();

            boundSession =
              session;

            connectionType =
              'target';

            (socket as any).__tabId =
              tabId;

            const registeredTargets =
              [...session.targets.values()]
                .map((target) => ({
                  tabId:
                    target.tabId,
                  tabName:
                    target.tabName,
                  url:
                    target.url,
                }));

            safeSend(
              socket,
              {
                type:
                  'TARGET_REGISTERED',

                remoteSessionId:
                  session.remoteSessionId,

                tabId,

                activeTargetTabId:
                  session.activeTargetTabId,

                targets:
                  registeredTargets,
              }
            );

            safeSend(
              session.controller,
              {
                type:
                  'TARGET_LIST',

                remoteSessionId:
                  session.remoteSessionId,

                activeTargetTabId:
                  session.activeTargetTabId,

                targets:
                  registeredTargets,
              }
            );

            if (
              session.controller
                ?.readyState ===
              WebSocket.OPEN
            ) {
              safeSend(
                socket,
                {
                  type:
                    'CONTROLLER_REGISTERED',

                  remoteSessionId:
                    session.remoteSessionId,

                  activeTargetTabId:
                    session.activeTargetTabId,
                }
              );
            }

            console.log(
              '[Relay] Customer browser tab registered:',
              session.remoteSessionId,
              tabId,
              url
            );

            return;
          }

          /**
           * --------------------------------------------------
           * ADVISOR / OFFICER REGISTER
           * --------------------------------------------------
           */
          if (
            parsed.type ===
            'CONTROLLER_REGISTER'
          ) {
            if (
              typeof parsed.token !==
              'string'
            ) {
              throw new Error(
                'Controller token missing'
              );
            }

            const payload =
              verifyToken(
                parsed.token
              );

            if (
              payload.type !==
              'controller'
            ) {
              throw new Error(
                'Invalid controller token'
              );
            }

            if (
              payload.remoteSessionId !==
              parsed.remoteSessionId
            ) {
              throw new Error(
                'Controller session mismatch'
              );
            }

            const session =
              sessions.get(
                parsed.remoteSessionId
              );

            if (!session) {
              throw new Error(
                'Remote session not found'
              );
            }

            if (
              payload.meetingId !==
              session.meetingId
            ) {
              throw new Error(
                'Meeting mismatch'
              );
            }

            if (
              payload.userId !==
              session.controllerId
            ) {
              throw new Error(
                'Controller mismatch'
              );
            }

            if (
              payload.role !==
              session.controllerRole
            ) {
              throw new Error(
                'Controller role mismatch'
              );
            }

            /**
             * Replace previous Controller if needed.
             */
            if (
              session.controller &&
              session.controller !==
                socket
            ) {
              closeSocketSafely(
                session.controller,
                'controller_replaced'
              );
            }

            session.controller =
              socket;

            session.lastActivity =
              Date.now();

            boundSession =
              session;

            connectionType =
              'controller';

            safeSend(
              socket,
              {
                type:
                  'CONTROLLER_REGISTERED',

                remoteSessionId:
                  session.remoteSessionId,
              }
            );

            const registeredTargets =
              [...session.targets.values()]
                .map((target) => ({
                  tabId:
                    target.tabId,
                  tabName:
                    target.tabName,
                  url:
                    target.url,
                }));

            safeSend(
              socket,
              {
                type:
                  'TARGET_LIST',

                remoteSessionId:
                  session.remoteSessionId,

                activeTargetTabId:
                  session.activeTargetTabId,

                targets:
                  registeredTargets,
              }
            );

            for (const target of session.targets.values()) {
              safeSend(
                target.socket,
                {
                  type:
                    'CONTROLLER_REGISTERED',

                  remoteSessionId:
                    session.remoteSessionId,

                  activeTargetTabId:
                    session.activeTargetTabId,
                }
              );
            }

            console.log(
              '[Relay] Controller registered:',
              session.remoteSessionId,
              'targets:',
              registeredTargets.length
            );

            return;
          }

          /**
           * Must register before sending other messages.
           */
          if (
            !boundSession ||
            !connectionType
          ) {
            throw new Error(
              'WebSocket is not registered'
            );
          }

          boundSession.lastActivity =
            Date.now();

          /**
           * --------------------------------------------------
           * HEARTBEAT
           * --------------------------------------------------
           */
          if (
            parsed.type ===
            'PING'
          ) {
            safeSend(
              socket,
              {
                type:
                  'PONG',

                timestamp:
                  Date.now(),
              }
            );

            return;
          }

          /**
           * --------------------------------------------------
           * CONTROLLER EVENT
           * --------------------------------------------------
           */
          if (
            parsed.type ===
            'CONTROL_EVENT'
          ) {
            if (
              connectionType !==
              'controller'
            ) {
              throw new Error(
                'Only controller can send control events'
              );
            }

            const event =
              parsed.event;

            if (
              !event ||
              typeof event.type !==
                'string'
            ) {
              throw new Error(
                'Invalid control event'
              );
            }

            if (
              !allowedEvents.has(
                event.type
              )
            ) {
              throw new Error(
                `Unsupported control event: ${event.type}`
              );
            }

            if (
              typeof event.x ===
              'number'
            ) {
              event.x =
                Math.max(
                  0,
                  Math.min(
                    1,
                    event.x
                  )
                );
            }

            if (
              typeof event.y ===
              'number'
            ) {
              event.y =
                Math.max(
                  0,
                  Math.min(
                    1,
                    event.y
                  )
                );
            }

            const requestedTabId =
              typeof parsed.targetTabId === 'string' &&
              parsed.targetTabId.trim()
                ? parsed.targetTabId.trim()
                : boundSession.activeTargetTabId;

            if (!requestedTabId) {
              safeSend(
                socket,
                {
                  type:
                    'CONTROL_DENIED',

                  reason:
                    'No customer tab is selected',
                }
              );

              return;
            }

            const target =
              boundSession.targets.get(
                requestedTabId
              );

            if (
              !target ||
              target.socket.readyState !==
                WebSocket.OPEN
            ) {
              safeSend(
                socket,
                {
                  type:
                    'CONTROL_DENIED',

                  reason:
                    'Selected customer tab is not connected',

                  targetTabId:
                    requestedTabId,
                }
              );

              return;
            }

            boundSession.activeTargetTabId =
              requestedTabId;

            safeSend(
              target.socket,
              {
                type:
                  'CONTROL_EVENT',

                remoteSessionId:
                  boundSession.remoteSessionId,

                targetTabId:
                  requestedTabId,

                event,
              }
            );

            return;
          }

          /**
           * --------------------------------------------------
           * MULTI-TAB CONTROLLER COMMANDS
           * --------------------------------------------------
           */
          if (
            allowedControllerCommands.has(
              parsed.type
            )
          ) {
            if (
              connectionType !==
              'controller'
            ) {
              throw new Error(
                'Only controller can manage customer tabs'
              );
            }

            const targetTabId =
              typeof parsed.targetTabId === 'string'
                ? parsed.targetTabId.trim()
                : '';

            if (!targetTabId) {
              throw new Error(
                'targetTabId is required'
              );
            }

            const target =
              boundSession.targets.get(
                targetTabId
              );

            if (!target) {
              safeSend(
                socket,
                {
                  type:
                    'CONTROL_DENIED',

                  reason:
                    'Customer tab not found',

                  targetTabId,
                }
              );

              return;
            }

            if (parsed.type === 'FOCUS_TAB') {
              boundSession.activeTargetTabId =
                targetTabId;

              safeSend(
                target.socket,
                {
                  type:
                    'FOCUS_TAB',

                  remoteSessionId:
                    boundSession.remoteSessionId,

                  targetTabId,
                }
              );

              safeSend(
                socket,
                {
                  type:
                    'ACTIVE_TAB_CHANGED',

                  remoteSessionId:
                    boundSession.remoteSessionId,

                  activeTargetTabId:
                    targetTabId,
                }
              );

              return;
            }

            if (parsed.type === 'NAVIGATE_TAB') {
              const url =
                typeof parsed.url === 'string'
                  ? parsed.url.slice(0, 2048)
                  : '';

              if (!url) {
                throw new Error(
                  'url is required'
                );
              }

              safeSend(
                target.socket,
                {
                  type:
                    'NAVIGATE_TAB',

                  remoteSessionId:
                    boundSession.remoteSessionId,

                  targetTabId,

                  url,
                }
              );

              return;
            }

            if (parsed.type === 'CLOSE_TAB') {
              safeSend(
                target.socket,
                {
                  type:
                    'CLOSE_TAB',

                  remoteSessionId:
                    boundSession.remoteSessionId,

                  targetTabId,
                }
              );

              return;
            }
          }

          /**
           * --------------------------------------------------
           * STOP CONTROL
           * --------------------------------------------------
           */
          if (
            parsed.type ===
            'CONTROL_STOP'
          ) {
            closeSession(
              boundSession.remoteSessionId,

              typeof parsed.reason ===
                'string'
                ? parsed.reason
                : 'stopped'
            );

            return;
          }

          throw new Error(
            `Unknown message type: ${parsed.type}`
          );
        } catch (error) {
          console.error(
            '[Relay Message]',
            error
          );

          safeSend(
            socket,
            {
              type:
                'UNAUTHORIZED',

              message:
                error instanceof
                  Error
                  ? error.message
                  : 'Invalid relay message',
            }
          );
        }
      }
    );

    /**
     * --------------------------------------------------------
     * DISCONNECT
     * --------------------------------------------------------
     */
    socket.on(
      'close',

      () => {
        if (
          !boundSession ||
          !connectionType
        ) {
          return;
        }

        if (
          !sessions.has(
            boundSession.remoteSessionId
          )
        ) {
          return;
        }

        if (
          connectionType === 'target'
        ) {
          const tabId =
            (socket as any).__tabId as
              string | undefined;

          if (!tabId) {
            return;
          }

          const registeredTarget =
            boundSession.targets.get(
              tabId
            );

          if (
            !registeredTarget ||
            registeredTarget.socket !==
              socket
          ) {
            return;
          }

          boundSession.targets.delete(
            tabId
          );

          if (
            boundSession.activeTargetTabId ===
            tabId
          ) {
            boundSession.activeTargetTabId =
              boundSession.targets.keys().next()
                .value;
          }

          const registeredTargets =
            [...boundSession.targets.values()]
              .map((target) => ({
                tabId:
                  target.tabId,
                tabName:
                  target.tabName,
                url:
                  target.url,
              }));

          safeSend(
            boundSession.controller,
            {
              type:
                'TARGET_LIST',

              remoteSessionId:
                boundSession.remoteSessionId,

              activeTargetTabId:
                boundSession.activeTargetTabId,

              targets:
                registeredTargets,
            }
          );

          console.log(
            '[Relay] Customer browser tab disconnected:',
            boundSession.remoteSessionId,
            tabId
          );

          if (
            boundSession.targets.size === 0
          ) {
            console.log(
              '[Relay] No customer tabs remain connected:',
              boundSession.remoteSessionId
            );
          }

          return;
        }

        if (
          connectionType === 'controller' &&
          boundSession.controller !==
            socket
        ) {
          return;
        }

        closeSession(
          boundSession.remoteSessionId,
          'controller_disconnected'
        );
      }
    );

    socket.on(
      'error',

      (error) => {
        console.error(
          '[Relay Socket]',
          error
        );
      }
    );
  }
);

/**
 * ------------------------------------------------------------
 * SESSION EXPIRY
 * ------------------------------------------------------------
 */
setInterval(
  () => {
    const now =
      Date.now();

    for (
      const [
        remoteSessionId,
        session,
      ] of sessions
    ) {
      const inactiveFor =
        now -
        session.lastActivity;

      if (
        inactiveFor >
        10 * 60 * 1000
      ) {
        closeSession(
          remoteSessionId,
          'session_expired'
        );
      }
    }
  },

  30_000
);

/**
 * ------------------------------------------------------------
 * START
 * ------------------------------------------------------------
 */
server.listen(
  PORT,

  '0.0.0.0',

  () => {
    console.log(
      '---------------------------------------'
    );

    console.log(
      'Remote Control Relay started (browser-only)'
    );

    console.log(
      `HTTP: http://localhost:${PORT}`
    );

    console.log(
      `Health: http://localhost:${PORT}/health`
    );

    console.log(
      `WebSocket: ws://localhost:${PORT}/remote-control`
    );

    console.log(
      'Allowed origins:',
      [...allowedOrigins]
    );

    console.log(
      '---------------------------------------'
    );
  }
);