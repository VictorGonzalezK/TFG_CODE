from pyexpat import features
import mysql.connector
from mysql.connector import errorcode
import datetime

#Set-Up the connection to the database
def set_cursor():
    cnx = mysql.connector.connect(user='root', password='mysqlvgk', host='127.0.0.1', database='urls')
    cursor = cnx.cursor()
    return cnx,cursor


#Function to create a new table in the database with a name
def create_table(table_name):
    #Dessign the configuartion the table will have
    TABLE_FROMAT = (
        "CREATE TABLE `{name}` ("
        "  `url` varchar(250) NOT NULL,"
        "  `malicious` int(1) NOT NULL,"
        "  PRIMARY KEY (`url`)"
        ") ENGINE=InnoDB".format(name=table_name))

    #Create the table
    table_description = TABLE_FROMAT
    cnx, cursor = set_cursor()
    try:
        print("Creating table: ", end='')
        cursor.execute(table_description)
    except mysql.connector.Error as err:
        if err.errno == 1050: #errorcode.ER_TABLE_EXISTS_ERROR
            print("already exists.")
        else:
            print(err.msg)
    else:
        print("OK")
    
    cnx.commit()
    cursor.close()
    cnx.close()
    return


def make_insertion(dict, table_name):
    
    #Connect
    cnx, cursor = set_cursor()

    #Insertion format
    add_row = "INSERT INTO {table} ({features}) VALUES ({values})".format(table=table_name, features=", ".join(dict.keys()), values=", ".join(["%s"] * len(dict)))
    #add_row = "INSERT INTO {table} ({features}) VALUES ({values})".format(table=table_name, features=", ".join(dict.keys()), values=", ".join(dict.values()))
    #Insert a row
    try:
        
        add_info = list(dict.values())
        cursor.execute(add_row, add_info)
        #cursor.execute(add_row)
    except mysql.connector.Error as err:
        if err.errno == 1054:
            #If there is no column add it and try again
            col_name = (err.msg.split("'")[1])
            print("New Column: {}".format(col_name)) 
            var_type = "TYPE"
            if type(dict[col_name]) is str:
                var_type="VARCHAR(250)"
            if type(dict[col_name]) is int:
                var_type="INT(255)"
            if type(dict[col_name]) is float:
                var_type="FLOAT(10,3)"
            if type(dict[col_name]) is datetime.datetime:
                var_type="DATETIME"
            if col_name== "full_text":
                var_type="TEXT"
            if col_name== "final_url":
                var_type="TEXT"
                
            result = 0
            if var_type != "TYPE":
                result = add_column(cursor, col_name, table_name, var_type)
            if result == 1:
                make_insertion(dict,table_name)
            elif result ==2:
                cnx.commit()
                cursor.close()
                cnx.close()
                return 1
            else:
                pass

        elif err.errno == 1114: #Table is full
            print("Table is full")
            cnx.commit()
            cursor.close()
            cnx.close()
            return 1
        else:    
            print("Error: {}".format(err))

    cnx.commit()
    cursor.close()
    cnx.close()
    return  0

def add_column(cursor, col_name, table_name, var_type):
    try:
        if len(col_name)<128:
            add_col = "ALTER TABLE {table} ADD COLUMN {col} {type}".format(table=table_name, col=col_name, type=var_type)
            cursor.execute(add_col)
            return 1
        else:
            return 0
        
    except mysql.connector.Error as err:
        if err.errno == 1117:
            return 2
        print("Error: {}".format(err))
        print("Can't add the new column")
        return 0


def check_table(url, table):
    checker = 0
    cnx, cursor = set_cursor()
    query = "SELECT url FROM {table} WHERE url='{url}'".format(table=table, url=url)
    cursor.execute(query)
    s_url = cursor.fetchone()
    if s_url is None:
        cnx.commit()
        cursor.close()
        cnx.close()
        return checker
    if url in s_url:
        checker = 1

    cnx.commit()
    cursor.close()
    cnx.close()
    return checker