using System.Runtime.InteropServices;

public partial class MAVLink
{
    public const byte MAV_AUTH_TYPE_LOGIN = 0;
    public const byte MAV_AUTH_TYPE_LOGOUT = 1;
    public const byte MAV_AUTH_RESULT_ACCEPTED = 0;
    public const byte MAV_AUTH_RESULT_FAILED = 1;

    /// <summary>
    /// AUTH_REQUEST wire layout from the ArduPilot GCS auth dialect (id 60010, crc 94).
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1, Size = 34)]
    public struct mavlink_auth_request_t
    {
        public byte target_system;
        public byte request_type;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] user_id;
    }

    /// <summary>
    /// AUTH_CHALLENGE wire layout (id 60011, crc 176). timestamp, then challenge[8], then user_salt[16].
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1, Size = 28)]
    public struct mavlink_auth_challenge_t
    {
        public uint timestamp;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] challenge;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] user_salt;
    }

    /// <summary>
    /// AUTH_RESPONSE wire layout (id 60012, crc 132). timestamp, then response[32].
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1, Size = 36)]
    public struct mavlink_auth_response_t
    {
        public uint timestamp;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] response;
    }

    /// <summary>
    /// AUTH_RESULT wire layout (id 60013, crc 168).
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1, Size = 1)]
    public struct mavlink_auth_result_t
    {
        public byte result;
    }
}
