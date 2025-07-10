# CDR Application 2

A Call Detail Record (CDR) processing application that handles encrypted telecommunication data records.

## Overview

This project processes CDR data from telecommunications systems, specifically handling SMS/messaging records with encrypted sensitive information. The application appears to decrypt and process call detail records for analysis and reporting purposes.

## Features

- **Encrypted Data Processing**: Handles encrypted fields containing sensitive information like phone numbers, IMSI, MSC data, and message content
- **SMS Record Analysis**: Processes SMS messaging records with delivery status tracking
- **Network Information**: Captures network type, location area information, and cell tower data
- **Device Information**: Tracks device details including IMEI and device models
- **Timestamp Tracking**: Records submission and delivery times for messages

## Data Structure

The application processes CSV files with the following key fields:

### Core Message Fields
- `RecordNr`: Record number/identifier
- `SP_ID`: Service Provider ID
- `MSG_TYPE`: Message type identifier
- `MSG_STATUS`: Message delivery status
- `MSG_ID`: Unique message identifier
- `SM_TEXT_LENGTH`: SMS text length
- `PRIORITY`: Message priority level

### Network & Location Fields
- `A_NETWORK_TYPE`: Network type for sender
- `A_LAI`, `B_LAI`: Location Area Information
- `A_CID`, `B_CID`: Cell ID information
- `A_TACID`, `B_TACID`: Tracking Area Code

### Encrypted Sensitive Fields
- `A_TADDR`, `B_TADDR`: Encrypted phone numbers
- `A_IMSI`, `B_IMSI`: Encrypted subscriber identities
- `A_MSC`, `B_MSC`: Encrypted Mobile Switching Center data
- `SM_CONTENT`: Encrypted message content
- `A_UADDR`, `B_UADDR`: Encrypted user addresses

### Device Information
- `A_IMEI`, `B_IMEI`: Device identifiers
- `A_DEVICE`, `B_DEVICE`: Device model information


## Data Sample

The application processes records like:
- Samsung Galaxy devices (A50, A72)
- Czech Republic network data (MCC: 420)
- SMS delivery tracking with timestamps
- Encrypted personal identifiable information

## Security Notes

⚠️ **Important**: This application handles sensitive telecommunications data including:
- Phone numbers
- Subscriber identities (IMSI)
- Message content
- Location information
- Device identifiers

Ensure proper security measures are in place when processing this data.

## Usage

1. Place your CDR input files in the project directory
2. Run the decryption/processing application
3. Review the output in `decrypted_output.csv`
4. Analyze the processed data for reporting or compliance purposes

## Technical Details

- **Data Format**: CSV with quoted fields
- **Encoding**: Handles various character encodings for international data
- **Encryption**: Uses base64 encoded encrypted fields for sensitive data
- **Network Standards**: Supports GSM/3G/4G network data formats

## Compliance

When using this application, ensure compliance with:
- Local telecommunications regulations
- Data protection laws (GDPR, etc.)
- Privacy requirements for subscriber data
- Industry standards for CDR processing

## Support

For issues or questions regarding CDR processing, consult your telecommunications system documentation or contact your system administrator.
