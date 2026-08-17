import 'dotenv/config';

import express from 'express';
import cors from 'cors';
import http from 'http';
import jwt from 'jsonwebtoken';

import WebSocket, {
  WebSocketServer,
} from 'ws';

const app = express();

app.use(cors());
app.use(express.json());

const PORT =
  Number(process.env.PORT) || 9877;

const SECRET =
  process.env.REMOTE_CONTROL_SECRET;

if (!SECRET) {
  throw new Error(
    'REMOTE_CONTROL_SECRET is missing'
  );
}

type ControllerRole =
  | 'officer'
  | 'advisor';

type ConnectionType =
  | 'agent'
  | 'controller';

interface TokenPayload {
  type: ConnectionType;

  remoteSessionId: string;

  meetingId: string;

  userId: string;

  role?: ControllerRole;
}

interface RelaySession {
  remoteSessionId: string;

  meetingId: string;

  customerId: string;

  controllerId: string;

  controllerRole:
    ControllerRole;

  agent?: WebSocket;

  controller?: WebSocket;

  createdAt: number;

  lastActivity: number;
}

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
    socket.readyState !==
      WebSocket.OPEN
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
      socket.readyState ===
        WebSocket.OPEN ||
      socket.readyState ===
        WebSocket.CONNECTING
    ) {
      socket.close(
        1000,
        reason.substring(0, 120)
      );
    }
  } catch {
    // Ignore close errors
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

  sessions.delete(
    remoteSessionId
  );

  safeSend(
    session.agent,
    {
      type:
        'CONTROL_STOPPED',

      remoteSessionId,

      reason,
    }
  );

  safeSend(
    session.controller,
    {
      type:
        'CONTROL_STOPPED',

      remoteSessionId,

      reason,
    }
  );

  closeSocketSafely(
    session.agent,
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
 * Health check
 */
app.get(
  '/health',
  (_req, res) => {
    res.json({
      success: true,

      service:
        'remote-control-relay',

      activeSessions:
        sessions.size,

      timestamp:
        new Date().toISOString(),
    });
  }
);

/**
 * Customer has approved remote control.
 *
 * Your application backend should eventually
 * call this endpoint.
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
      } = req.body;

      if (
        typeof remoteSessionId !==
          'string' ||
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
        typeof meetingId !==
          'string' ||
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
        typeof customerId !==
          'string' ||
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
        typeof controllerId !==
          'string' ||
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
        controllerRole !==
          'advisor' &&
        controllerRole !==
          'officer'
      ) {
        return res
          .status(403)
          .json({
            success: false,
            message:
              'Controller role must be advisor or officer',
          });
      }

      const existing =
        sessions.get(
          remoteSessionId
        );

      if (existing) {
        closeSession(
          remoteSessionId,
          'session_reauthorized'
        );
      }

      const session:
        RelaySession =
      {
        remoteSessionId:
          remoteSessionId.trim(),

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

      const agentToken =
        createToken({
          type:
            'agent',

          remoteSessionId:
            session.remoteSessionId,

          meetingId:
            session.meetingId,

          userId:
            session.customerId,
        });

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
        '[Relay] Authorized:',
        session.remoteSessionId
      );

      return res.json({
        success: true,

        remoteSessionId:
          session.remoteSessionId,

        agentToken,

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

const server =
  http.createServer(app);

const wss =
  new WebSocketServer({
    server,

    path:
      '/remote-control',
  });

wss.on(
  'connection',

  (socket) => {
    console.log(
      '[Relay] WebSocket connected'
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
           * CUSTOMER AGENT
           */
          if (
            parsed.type ===
              'AGENT_REGISTER'
          ) {
            if (
              typeof parsed.token !==
                'string'
            ) {
              throw new Error(
                'Agent token missing'
              );
            }

            const payload =
              verifyToken(
                parsed.token
              );

            if (
              payload.type !==
                'agent'
            ) {
              throw new Error(
                'Invalid agent token'
              );
            }

            if (
              payload.remoteSessionId !==
                parsed.remoteSessionId
            ) {
              throw new Error(
                'Agent session mismatch'
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

            session.agent =
              socket;

            session.lastActivity =
              Date.now();

            boundSession =
              session;

            connectionType =
              'agent';

            safeSend(
              socket,
              {
                type:
                  'AGENT_REGISTERED',

                remoteSessionId:
                  session.remoteSessionId,
              }
            );

            safeSend(
              session.controller,
              {
                type:
                  'AGENT_REGISTERED',

                remoteSessionId:
                  session.remoteSessionId,
              }
            );

            console.log(
              '[Relay] Agent registered:',
              session.remoteSessionId
            );

            return;
          }

          /**
           * ADVISOR / OFFICER
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

            if (
              session.agent
            ) {
              safeSend(
                socket,
                {
                  type:
                    'AGENT_REGISTERED',

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
           * Require registration before anything else.
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
           * HEARTBEAT
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
           * INPUT EVENTS
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

            const allowedEvents =
              new Set([
                'MOUSE_MOVE',

                'MOUSE_DOWN',

                'MOUSE_UP',

                'MOUSE_CLICK',

                'MOUSE_DOUBLE_CLICK',

                'SCROLL',

                'KEY_DOWN',

                'KEY_UP',
              ]);

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
             * Normalize coordinate protection.
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

            if (
              !boundSession.agent ||
              boundSession.agent
                .readyState !==
                WebSocket.OPEN
            ) {
              safeSend(
                socket,
                {
                  type:
                    'CONTROL_DENIED',

                  reason:
                    'Customer Agent is not connected',
                }
              );

              return;
            }

            safeSend(
              boundSession.agent,
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
           * STOP CONTROL
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
          connectionType ===
            'agent'
        ) {
          closeSession(
            boundSession.remoteSessionId,
            'agent_disconnected'
          );

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
 * Session timeout
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

server.listen(
  PORT,

  '0.0.0.0',

  () => {
    console.log(
      '---------------------------------------'
    );

    console.log(
      'Remote Control Relay started'
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
      '---------------------------------------'
    );
  }
);