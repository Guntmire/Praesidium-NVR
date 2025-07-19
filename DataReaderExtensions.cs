using Microsoft.Data.Sqlite;

namespace EnterpriseNVR
{
    public static class DataReaderExtensions
    {
        public static string GetString(this SqliteDataReader reader, string column)
            => reader.GetString(reader.GetOrdinal(column));

        public static int GetInt32(this SqliteDataReader reader, string column)
            => reader.GetInt32(reader.GetOrdinal(column));

        public static long GetInt64(this SqliteDataReader reader, string column)
            => reader.GetInt64(reader.GetOrdinal(column));

        public static bool GetBoolean(this SqliteDataReader reader, string column)
            => reader.GetBoolean(reader.GetOrdinal(column));

        public static double GetDouble(this SqliteDataReader reader, string column)
            => reader.GetDouble(reader.GetOrdinal(column));

        public static float GetFloat(this SqliteDataReader reader, string column)
            => reader.GetFloat(reader.GetOrdinal(column));

        public static decimal GetDecimal(this SqliteDataReader reader, string column)
            => reader.GetDecimal(reader.GetOrdinal(column));

        public static DateTime GetDateTime(this SqliteDataReader reader, string column)
            => reader.GetDateTime(reader.GetOrdinal(column));
    }
}
