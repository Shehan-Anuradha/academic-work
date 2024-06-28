#include <TinyGPS++.h>
#include <Wire.h>
#include <TinyGsmClient.h>
#include <SoftwareSerial.h>

// Set your GSM network credentials
const char* apn = "your_apn";
const char* gprsUser = "";
const char* gprsPass = "";

// Set the GSM PIN if required
const char* simPIN = "";

// Create a software serial object to communicate with the GPS module
SoftwareSerial ss(12, 34); // RX, TX (change these to the desired pins)

// Create a TinyGPS++ object
TinyGPSPlus gps;

// Create a GSM client
TinyGsmClient client;

// Set serial for debug console (optional)
#define SerialMon Serial

void setup()
{
  // Start the serial communication for debugging
  SerialMon.begin(115200);

  // Start the serial communication with the GPS module
  ss.begin(9600);

  // Wait for GSM module to respond
  delay(3000);
  SerialMon.println("Initializing GSM...");
  TinyGsmAutoBaud(SerialMon);
  
  // Start the GSM connection
  SerialMon.println("Connecting to GSM network...");
  TinyGsm modem(SerialMon);
  modem.restart();

  // Unlock your SIM card with a PIN if needed
  if (simPIN && modem.getSimStatus() != 3) {
    modem.simUnlock(simPIN);
  }

  // Connect to the GPRS network
  if (!modem.gprsConnect(apn, gprsUser, gprsPass)) {
    SerialMon.println("Failed to connect to the GPRS network!");
  } else {
    SerialMon.println("GPRS connected!");
  }
}

void loop()
{
  // Read data from the GPS module
  while (ss.available() > 0) {
    if (gps.encode(ss.read())) {
      // Print GPS data when a new sentence is parsed
      if (gps.location.isValid()) {
        SerialMon.print("Latitude: ");
        SerialMon.println(gps.location.lat(), 6);
        SerialMon.print("Longitude: ");
        SerialMon.println(gps.location.lng(), 6);
      }
      if (gps.date.isValid()) {
        SerialMon.print("Date: ");
        SerialMon.print(gps.date.day());
        SerialMon.print("/");
        SerialMon.print(gps.date.month());
        SerialMon.print("/");
        SerialMon.println(gps.date.year());
      }
      if (gps.time.isValid()) {
        SerialMon.print("Time: ");
        SerialMon.print(gps.time.hour());
        SerialMon.print(":");
        SerialMon.print(gps.time.minute());
        SerialMon.print(":");
        SerialMon.print(gps.time.second());
        SerialMon.print(".");
        SerialMon.println(gps.time.centisecond());
      }
      if (gps.altitude.isValid()) {
        SerialMon.print("Altitude: ");
        SerialMon.print(gps.altitude.meters());
        SerialMon.println(" meters");
      }
      if (gps.speed.isValid()) {
        SerialMon.print("Speed: ");
        SerialMon.print(gps.speed.kmph());
        SerialMon.println(" km/h");
      }
      if (gps.course.isValid()) {
        SerialMon.print("Course: ");
        SerialMon.print(gps.course.deg());
        SerialMon.println(" degrees");
      }
      SerialMon.println();
    }
  }
}
