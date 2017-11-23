# pip install pymysql
import pymysql
import pandas as pd

# Connect to the database
# connection = pymysql.connect(host='academic-mysql.cc.gatech.edu',
#                              user='cs4400_Group_41',
#                              password='dfURMV5v',
#                              db='cs4400_Group_41',
# )

xls = pd.ExcelFile('MARTA+Database+Info.xlsx')

# try:
#     with connection.cursor() as cursor:
for table in xls.sheet_names:
    if table == 'Station':
        df = pd.read_excel('MARTA+Database+Info.xlsx', sheet_name=table)
        for row in df.itertuples():
            if type(row[2]) == float:
                sql = 'INSERT INTO ' + table + ' VALUES ("' + str(row[1]) + '", NULL);'
            else:
                sql = 'INSERT INTO ' + table + ' VALUES ("' + str(row[1]) + '", "' + str(row[2]) + '", ' + str(row[3]) + ', ' + str(row[4]) + ', ' + str(row[5]) + ');'

            #cursor.execute(sql)
            print(sql)
# finally:
#     connection.close()
#     print("Done")
