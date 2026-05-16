CREATE WAREHOUSE CYBER_WH
WITH
WAREHOUSE_SIZE = 'XSMALL'
AUTO_SUSPEND = 60
AUTO_RESUME = TRUE;
CREATE DATABASE CYBERSECURITY_DB;
CREATE SCHEMA SECURITY_SCHEMA;
USE DATABASE CYBERSECURITY_DB;

USE SCHEMA SECURITY_SCHEMA;
USE WAREHOUSE CYBER_WH;
CREATE TABLE SYSTEMUSER (
    userId INT,
    userName STRING,
    department STRING,
    accessLevel STRING,
    accountStatus STRING
);

CREATE TABLE SECURITYLOG (
    logId STRING,
    systemName STRING,
    logType STRING,
    logTimestamp TIMESTAMPP
);
CREATE TABLE INCIDENT (
    incidentId STRING PRIMARY KEY,
    incidentType STRING,
    severityLevel STRING,
    detectedAt TIMESTAMP,
    incidentStatus STRING
);
CREATE TABLE THREATALERT (
    alertId STRING,
    incidentId STRING,
    threatScore INT CHECK (threatScore BETWEEN 0 AND 100),
    alertReason STRING,
    alertStatus STRING
);
CREATE TABLE ACCESSAUDIT (
    auditId STRING,
    userId INT,
    loginTimestamp TIMESTAMP,
    loginStatus STRING,
    ipAddress STRING
);
CREATE STAGE cyber_stage;
CREATE FILE FORMAT cyber_csv_format
TYPE = CSV
SKIP_HEADER = 1
FIELD_OPTIONALLY_ENCLOSED_BY = '"';
CREATE TABLE RAW_CYBERSECURITY_DATA (
    userId INT,
    userName STRING,
    department STRING,
    accessLevel STRING,
    accountStatus STRING,
    logId STRING,
    systemName STRING,
    logType STRING,
    logTimestamp TIMESTAMP,
    incidentId STRING,
    incidentType STRING,
    severityLevel STRING,
    detectedAt TIMESTAMP,
    incidentStatus STRING,
    alertId STRING,
    threatScore INT,
    alertReason STRING,
    alertStatus STRING,
    auditId STRING,
    loginTimestamp TIMESTAMP,
    loginStatus STRING,
    ipAddress STRING
);
COPY INTO RAW_CYBERSECURITY_DATA
FROM @cyber_stage/cybersecurity_dataset_snowflake.csv
FILE_FORMAT = cyber_csv_format;
CREATE OR REPLACE TABLE CLEAN_CYBERSECURITY_DATA AS
SELECT DISTINCT *
FROM RAW_CYBERSECURITY_DATA;
INSERT INTO SYSTEMUSER
SELECT DISTINCT
    userId,
    userName,
    department,
    accessLevel,
    accountStatus
FROM CLEAN_CYBERSECURITY_DATA;
INSERT INTO SECURITYLOG
SELECT DISTINCT
    logId,
    systemName,
    logType,
    logTimestamp
FROM CLEAN_CYBERSECURITY_DATA;
INSERT INTO INCIDENT
SELECT DISTINCT
    incidentId,
    incidentType,
    severityLevel,
    detectedAt,
    incidentStatus
FROM CLEAN_CYBERSECURITY_DATA;
INSERT INTO THREATALERT
SELECT DISTINCT
    alertId,
    incidentId,
    threatScore,
    alertReason,
    alertStatus
FROM CLEAN_CYBERSECURITY_DATA;
INSERT INTO ACCESSAUDIT
SELECT DISTINCT
    auditId,
    userId,
    loginTimestamp,
    loginStatus,
    ipAddress
FROM CLEAN_CYBERSECURITY_DATA;
SELECT
    i.incidentId,
    i.severityLevel,
    t.threatScore
FROM INCIDENT i
JOIN THREATALERT t
ON i.incidentId = t.incidentId;
SELECT
    severityLevel,
    COUNT(*) AS total_incidents
FROM INCIDENT
GROUP BY severityLevel;
SELECT *
FROM THREATALERT
WHERE threatScore > 80;
CREATE STREAM incident_stream
ON TABLE INCIDENT;
CREATE TASK high_risk_task
WAREHOUSE = CYBER_WH
SCHEDULE = '5 MINUTE'
AS
INSERT INTO THREATALERT
SELECT
    alertId,
    incidentId,
    threatScore,
    alertReason,
    alertStatus
FROM CLEAN_CYBERSECURITY_DATA
WHERE threatScore > 80;
ALTER TASK high_risk_task RESUME;
CREATE DYNAMIC TABLE INCIDENT_SUMMARY
TARGET_LAG = '5 minutes'
WAREHOUSE = CYBER_WH
AS
SELECT
    severityLevel,
    COUNT(*) AS total_incidents
FROM INCIDENT
GROUP BY severityLevel;
CREATE ROLE SECURITY_ADMIN;

CREATE ROLE ANALYST;
GRANT SELECT ON ALL TABLES
IN SCHEMA SECURITY_SCHEMA
TO ROLE ANALYST;

