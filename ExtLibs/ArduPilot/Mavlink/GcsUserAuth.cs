using log4net;
using MissionPlanner.Utilities;
using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace MissionPlanner.ArduPilot.Mavlink
{
    /// <summary>
    /// Challenge login against ArduPilot AP_GCS_Auth.
    /// Credentials come from config.xml. No login screen is used.
    /// </summary>
    public static class GcsUserAuth
    {
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

        const int UserIdLen = 32;
        const int ChallengeLen = 8;
        const int SaltLen = 16;
        const int AuthTimeoutMs = 10000;

        public static bool IsEnabled
        {
            get { return Settings.Instance.GetBoolean(Settings.GcsAuthEnableKey, false); }
        }

        public static bool Login(global::MissionPlanner.MAVLinkInterface port, IProgressReporterDialogue progress, out string error)
        {
            error = null;
            string userId = Settings.Instance[Settings.GcsAuthUserIdKey] ?? "";
            string password = Settings.Instance[Settings.GcsAuthPasswordKey] ?? "";

            if (userId.Length == 0 || password.Length == 0)
            {
                error = "User authentication is enabled but gcs_auth_userid or gcs_auth_password in config.xml is empty.";
                return false;
            }

            foreach (char c in userId)
            {
                if (c > 127)
                {
                    error = "gcs_auth_userid must be ASCII.";
                    return false;
                }
            }

            byte[] userBytes = Encoding.ASCII.GetBytes(userId);
            if (userBytes.Length == 0 || userBytes.Length > UserIdLen - 1)
            {
                error = "gcs_auth_userid must be 1 to 31 ASCII characters.";
                return false;
            }

            var request = new MAVLink.mavlink_auth_request_t
            {
                target_system = 0,
                request_type = MAVLink.MAV_AUTH_TYPE_LOGIN,
                user_id = new byte[UserIdLen]
            };
            Array.Copy(userBytes, request.user_id, userBytes.Length);

            log.Info("GCS auth login request user='" + userId + "'");
            port.SetGcsAuthReading(true);
            try
            {
                return LoginAfterRequest(port, progress, request, userBytes, password, out error);
            }
            finally
            {
                port.SetGcsAuthReading(false);
            }
        }

        static bool LoginAfterRequest(global::MissionPlanner.MAVLinkInterface port, IProgressReporterDialogue progress,
            MAVLink.mavlink_auth_request_t request, byte[] userBytes, string password, out string error)
        {
            error = null;
            port.generatePacket((int)MAVLink.MAVLINK_MSG_ID.AUTH_REQUEST, request, 0, 0, true, false);

            byte[] challenge = null;
            byte[] salt = null;
            uint timestamp = 0;
            byte sysid = 0;
            byte compid = 0;
            bool sawChallenge = false;
            string exitText = null;
            bool unsignedSession = false;
            int otherPackets = 0;
            uint lastOther = 0;

            DateTime deadline = DateTime.UtcNow.AddMilliseconds(AuthTimeoutMs);
            while (DateTime.UtcNow < deadline)
            {
                if (progress != null && progress.doWorkArgs != null && progress.doWorkArgs.CancelRequested)
                {
                    error = "User authentication cancelled.";
                    return false;
                }

                if (port.BaseStream == null || !port.BaseStream.IsOpen)
                {
                    error = "User authentication stopped because the port closed.";
                    return false;
                }

                MAVLink.MAVLinkMessage msg = ReadOne(port);
                if (msg == null || msg.Length <= 5)
                    continue;

                if (msg.msgid == (uint)MAVLink.MAVLINK_MSG_ID.STATUSTEXT)
                {
                    NoteStatus(msg, ref exitText, ref unsignedSession);
                    continue;
                }

                if (msg.msgid == (uint)MAVLink.MAVLINK_MSG_ID.AUTH_CHALLENGE)
                {
                    byte[] payload = Payload(msg, 28);
                    timestamp = BitConverter.ToUInt32(payload, 0);
                    challenge = new byte[ChallengeLen];
                    salt = new byte[SaltLen];
                    Array.Copy(payload, 4, challenge, 0, ChallengeLen);
                    Array.Copy(payload, 12, salt, 0, SaltLen);
                    sysid = msg.sysid;
                    compid = msg.compid;
                    sawChallenge = true;
                    log.Info("GCS auth challenge ts=" + timestamp + " sys=" + sysid + " comp=" + compid);
                    break;
                }

                if (msg.msgid == (uint)MAVLink.MAVLINK_MSG_ID.AUTH_RESULT)
                {
                    byte[] payload = Payload(msg, 1);
                    sysid = msg.sysid;
                    compid = msg.compid;
                    if (payload[0] == MAVLink.MAV_AUTH_RESULT_ACCEPTED)
                    {
                        log.Info("GCS auth accepted without challenge");
                        port.SetGcsAuthSession(sysid, compid, null);
                        return true;
                    }

                    error = exitText ?? "User authentication failed.";
                    return false;
                }

                otherPackets++;
                lastOther = msg.msgid;
            }

            if (!sawChallenge)
            {
                error = exitText ?? (otherPackets == 0
                    ? "User authentication timed out waiting for AUTH_CHALLENGE."
                    : "User authentication timed out waiting for AUTH_CHALLENGE. Last message id " + lastOther + ".");
                return false;
            }

            byte[] passwordHash = Sha256(Concat(Encoding.UTF8.GetBytes(password), salt));
            byte[] responseHash = Sha256(Concat(passwordHash, challenge));
            var response = new MAVLink.mavlink_auth_response_t
            {
                timestamp = timestamp,
                response = responseHash
            };
            port.generatePacket((int)MAVLink.MAVLINK_MSG_ID.AUTH_RESPONSE, response, sysid, compid, true, false);

            deadline = DateTime.UtcNow.AddMilliseconds(AuthTimeoutMs);
            while (DateTime.UtcNow < deadline)
            {
                if (progress != null && progress.doWorkArgs != null && progress.doWorkArgs.CancelRequested)
                {
                    error = "User authentication cancelled.";
                    return false;
                }

                if (port.BaseStream == null || !port.BaseStream.IsOpen)
                {
                    error = "User authentication stopped because the port closed.";
                    return false;
                }

                MAVLink.MAVLinkMessage msg = ReadOne(port);
                if (msg == null || msg.Length <= 5)
                    continue;

                if (msg.msgid == (uint)MAVLink.MAVLINK_MSG_ID.STATUSTEXT)
                {
                    NoteStatus(msg, ref exitText, ref unsignedSession);
                    continue;
                }

                if (msg.msgid != (uint)MAVLink.MAVLINK_MSG_ID.AUTH_RESULT)
                    continue;

                byte[] payload = Payload(msg, 1);
                if (payload[0] != MAVLink.MAV_AUTH_RESULT_ACCEPTED)
                {
                    error = exitText ?? "User authentication failed.";
                    log.Info(error);
                    return false;
                }

                byte[] signingKey = null;
                if (!unsignedSession)
                    signingKey = Sha256(Concat(userBytes, passwordHash, challenge));

                port.SetGcsAuthSession(msg.sysid, msg.compid, signingKey);
                log.Info(signingKey == null
                    ? "GCS auth accepted, unsigned session"
                    : "GCS auth accepted, signing key applied");
                return true;
            }

            error = exitText ?? "User authentication timed out waiting for AUTH_RESULT.";
            return false;
        }

        public static void SendLogout(global::MissionPlanner.MAVLinkInterface port, byte targetSystem, byte targetComponent)
        {
            string userId = Settings.Instance[Settings.GcsAuthUserIdKey] ?? "";
            byte[] userBytes = new byte[0];
            bool ascii = true;
            foreach (char c in userId)
            {
                if (c > 127)
                {
                    ascii = false;
                    break;
                }
            }
            if (ascii)
                userBytes = Encoding.ASCII.GetBytes(userId);

            var request = new MAVLink.mavlink_auth_request_t
            {
                target_system = targetSystem,
                request_type = MAVLink.MAV_AUTH_TYPE_LOGOUT,
                user_id = new byte[UserIdLen]
            };
            if (userBytes.Length > 0 && userBytes.Length < UserIdLen)
                Array.Copy(userBytes, request.user_id, userBytes.Length);

            log.Info("GCS auth logout");
            port.generatePacket((int)MAVLink.MAVLINK_MSG_ID.AUTH_REQUEST, request, targetSystem, targetComponent, true, false);
        }

        static MAVLink.MAVLinkMessage ReadOne(global::MissionPlanner.MAVLinkInterface port)
        {
            try
            {
                return port.readPacket();
            }
            catch (Exception ex)
            {
                log.Info("GCS auth read: " + ex.Message);
                return null;
            }
        }

        static void NoteStatus(MAVLink.MAVLinkMessage msg, ref string exitText, ref bool unsignedSession)
        {
            try
            {
                var status = msg.ToStructure<MAVLink.mavlink_statustext_t>();
                if (status.text == null)
                    return;
                string text = Encoding.ASCII.GetString(status.text).TrimEnd('\0', ' ');
                if (text.Length == 0)
                    return;
                log.Info("GCS auth status: " + text);
                if (text.StartsWith("AUTH_EXIT_"))
                    exitText = text;
                if (text.IndexOf("unsigned session", StringComparison.Ordinal) >= 0)
                    unsignedSession = true;
            }
            catch (Exception ex)
            {
                log.Info("GCS auth statustext: " + ex.Message);
            }
        }

        static byte[] Payload(MAVLink.MAVLinkMessage msg, int expectedLen)
        {
            int header = msg.ismavlink2 ? MAVLink.MAVLINK_NUM_HEADER_BYTES : 6;
            var payload = new byte[expectedLen];
            int copy = Math.Max(0, Math.Min(msg.payloadlength, expectedLen));
            if (msg.buffer != null && msg.buffer.Length >= header + copy)
                Array.Copy(msg.buffer, header, payload, 0, copy);
            return payload;
        }

        static byte[] Concat(params byte[][] parts)
        {
            int len = 0;
            foreach (var part in parts)
                len += part.Length;
            var all = new byte[len];
            int offset = 0;
            foreach (var part in parts)
            {
                Array.Copy(part, 0, all, offset, part.Length);
                offset += part.Length;
            }
            return all;
        }

        static byte[] Sha256(byte[] data)
        {
            using (SHA256 sha = SHA256.Create())
            {
                return sha.ComputeHash(data);
            }
        }
    }
}
