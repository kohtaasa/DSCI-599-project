"""
This script scrapes the MergeTB website and store the urls and metadata in a SQLite database.
It does not automatically download the data, but it stores data necessary to download and process the data.
"""

import requests
import sqlite3
from bs4 import BeautifulSoup


def insert_into_db(conn, href, metadata):
    cur = conn.cursor()
    cur.execute(f"INSERT INTO row_data (url, metadata) VALUES (?, ?)", (href, metadata))


url = 'https://mergetb.org/projects/searchlight/dataset/'
response = requests.get(url)

soup = BeautifulSoup(response.text, 'html.parser')
rows = soup.find_all('table')[0].find_all('tr')

# Establish the database connection once at the beginning
conn = sqlite3.connect('../data/datasets.db')
cur = conn.cursor()
# Ensure the table exists
cur.execute('''CREATE TABLE IF NOT EXISTS row_data
             (id INTEGER PRIMARY KEY, url TEXT, metadata TEXT)''')

for row in rows:
    cols = row.find_all('td')
    if len(cols) > 1:
        a_tag = cols[1].find('a')
        metadata_col = cols[5].text if len(cols) > 5 else ""

        if a_tag and 'app: vtc' in metadata_col:
            href = a_tag.get('href')
            metadata = metadata_col.strip()
            # Insert data into the database using the existing connection
            insert_into_db(conn, href, metadata)
            print(f"Inserted into DB: {href}, {metadata}")

# Commit once after all insertions are done
conn.commit()

# Close the connection after all operations are done
conn.close()
