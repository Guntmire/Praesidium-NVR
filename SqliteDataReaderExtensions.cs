using Microsoft.Data.Sqlite;

namespace EnterpriseNVR
{
    public static class SqliteDataReaderExtensions
    {
        public static string GetString(this SqliteDataReader reader, string columnName)
        {
            return reader.GetString(reader.GetOrdinal(columnName));
        }

        public static int GetInt32(this SqliteDataReader reader, string columnName)
        {
            return reader.GetInt32(reader.GetOrdinal(columnName));
        }
    }
}
