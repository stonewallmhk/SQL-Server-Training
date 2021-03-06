--Create Master Key

USE Master;
GO
CREATE MASTER KEY ENCRYPTION
BY PASSWORD='InsertStrongPasswordHere';
GO

--Create Certificate protected by Master Key

CREATE CERTIFICATE TDE_Cert
WITH 
SUBJECT='Database_Encryption';
GO

--Create Database Encryption Key (DEK)

USE <DB>
GO
CREATE DATABASE ENCRYPTION KEY
WITH ALGORITHM = AES_256
ENCRYPTION BY SERVER CERTIFICATE TDE_Cert;
GO

--Enable Encryption


ALTER DATABASE <DB>
SET ENCRYPTION ON;
GO

--Backup Certificate

BACKUP CERTIFICATE TDE_Cert
TO FILE = 'C:\temp\TDE_Cert'
WITH PRIVATE KEY (file='C:\temp\TDE_CertKey.pvk',
ENCRYPTION BY PASSWORD='InsertStrongPasswordHere') 

--Restoring a Certificate

USE MASTER
GO
CREATE CERTIFICATE TDECert
FROM FILE = 'C:\Temp\TDE_Cert'
WITH PRIVATE KEY (FILE = 'C:\TDECert_Key.pvk',
DECRYPTION BY PASSWORD = 'InsertStrongPasswordHere' );

