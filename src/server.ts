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

type RelaySession = {
  remoteSessionId: string;

  meetingId: string;

  customerId: string;

  controllerId: string;

  controllerRole: ControllerRole;

  target?: WebSocket;

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

  safeSend(
    session.target,
    stoppedMessage
  );

  safeSend(
    session.controller,
    stoppedMessage
  );

  closeSocketSafely(
    session.target,
    reason
  );

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

            /**
             * Replace old target connection if needed.
             */
            if (
              session.target &&
              session.target !== socket
            ) {
              closeSocketSafely(
                session.target,
                'target_replaced'
              );
            }

            session.target =
              socket;

            session.lastActivity =
              Date.now();

            boundSession =
              session;

            connectionType =
              'target';

            safeSend(
              socket,
              {
                type:
                  'TARGET_REGISTERED',

                remoteSessionId:
                  session.remoteSessionId,
              }
            );

            /**
             * Tell Controller Customer is available.
             */
            safeSend(
              session.controller,
              {
                type:
                  'TARGET_REGISTERED',

                remoteSessionId:
                  session.remoteSessionId,
              }
            );

            /**
             * If controller already exists,
             * tell customer too.
             */
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
                }
              );
            }

            console.log(
              '[Relay] Customer browser registered:',
              session.remoteSessionId
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

            /**
             * Target already connected?
             */
            if (
              session.target
                ?.readyState ===
              WebSocket.OPEN
            ) {
              safeSend(
                socket,
                {
                  type:
                    'TARGET_REGISTERED',

                  remoteSessionId:
                    session.remoteSessionId,
                }
              );

              safeSend(
                session.target,
                {
                  type:
                    'CONTROLLER_REGISTERED',

                  remoteSessionId:
                    session.remoteSessionId,
                }
              );
            }

            console.log(
              '[Relay] Controller registered:',
              session.remoteSessionId
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

            /**
             * Protect normalized coordinates.
             */
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

            /**
             * Customer browser must be connected.
             */
            if (
              !boundSession.target ||
              boundSession.target
                .readyState !==
                WebSocket.OPEN
            ) {
              safeSend(
                socket,
                {
                  type:
                    'CONTROL_DENIED',

                  reason:
                    'Customer browser is not connected',
                }
              );

              return;
            }

            /**
             * Forward remote UI input.
             */
            safeSend(
              boundSession.target,
              {
                type:
                  'CONTROL_EVENT',

                remoteSessionId:
                  boundSession.remoteSessionId,

                event,
              }
            );

            return;
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

        /**
         * Ignore close event if this socket was already
         * replaced by another socket of the same role.
         */
        if (
          connectionType === 'target' &&
          boundSession.target !== socket
        ) {
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

          connectionType ===
            'target'
            ? 'customer_disconnected'
            : 'controller_disconnected'
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