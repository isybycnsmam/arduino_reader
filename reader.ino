#include <SPI.h>
#include <MFRC522.h>

#define RST_PIN         0
#define SS_PIN          2

MFRC522 mfrc522(SS_PIN, RST_PIN);
MFRC522::MIFARE_Key key;
byte scannedCard[64][16];
String scannedUid = "NULL";


void setup() {
    Serial.begin(115200);
    while (!Serial) ;
    
    SPI.begin();
    mfrc522.PCD_Init();

    for (byte i = 0; i < 6; i++) 
        key.keyByte[i] = 0xFF;

    printMenu();
}

void loop() {
    int choice = Serial.read();
    
    if(choice == -1 || !printGeneralAndCheck()) 
        return;

    if(choice == '1') //read show and store
        readAndPrint();
    else if(choice == '2') { // write from cache
        if(scannedUid == "NULL") {
            Serial.println("Error - cache is empty");
            return;
        }
        else
            writeToMemory();
    }
    else if(choice == '3') {//write from string
        Serial.println("Enter new card memory value");
        //String cardValue = Serial.read();
        
    }
    else if(choice == '4') { // get card string from cache

    }

    printMenu();

}


void printMenu() {
    Serial.println("\n\n1. Read");
    Serial.print("2. Write (" + scannedUid + ")\n");
    Serial.println("3. Write from source");
    Serial.println("4. Get card content string (" + scannedUid + ")\n");
}

bool printGeneralAndCheck() {
    if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) 
        return false;

    if (mfrc522.PICC_GetType(mfrc522.uid.sak) != MFRC522::PICC_TYPE_MIFARE_1K) {
        Serial.println("Unsuported key card");
        return false;
    }

    Serial.print("UID:");
    dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
    Serial.println("\n");

    return true;
}


void readAndPrint() {
    MFRC522::StatusCode status;
    byte buffer[18];
    scannedUid = getUid();
    
    for(byte block = 0; block < 64; block++) {
        status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key, &(mfrc522.uid));
        if (status != MFRC522::STATUS_OK) {
            Serial.print("PCD_Authenticate() failed: ");
            Serial.println(mfrc522.GetStatusCodeName(status));
            return;
        }


        byte byteCount = sizeof(buffer);
        status = mfrc522.MIFARE_Read(block, buffer, &byteCount);
        if (status != MFRC522::STATUS_OK) {
            Serial.print(F("MIFARE_Read() failed: "));
            Serial.println(mfrc522.GetStatusCodeName(status));
            return;
        }
        
        for (int i = 0; i < 16; i++)
            scannedCard[block][i] = buffer[i];

        if(block % 4 == 0) {
            Serial.print("Block: ");
            Serial.println(block / 4);
        }
        
        dump_byte_array(buffer, 16);
        
        Serial.println();
        
    }
    
    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
}

String getUid() {
    String alphabtet = "0123456789ABCDEF";
    String result = "";
    for (int i = 0; i < 4; i++) {
        result += (char)alphabtet[mfrc522.uid.uidByte[i] % 16];
        result += (char)alphabtet[mfrc522.uid.uidByte[i] / 16];
        if(i != 3) result += ":";
    }
    return result;
}


void writeToMemory() {
    MFRC522::StatusCode status;

    for (int i = 0; i < 64; i++) {
        status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, 0x04, &key, &(mfrc522.uid));
        if (status != MFRC522::STATUS_OK) {
            Serial.print(F("PCD_Authenticate() failed: "));
            Serial.println(mfrc522.GetStatusCodeName(status));
            return;
        }

        status = (MFRC522::StatusCode) mfrc522.MIFARE_Write((byte)i, scannedCard[i], 16);
        if (status != MFRC522::STATUS_OK) {
            Serial.print(F("MIFARE_Write() failed: "));
            Serial.println(mfrc522.GetStatusCodeName(status));
        }
    }

    Serial.println("Done");
}

void dump_byte_array(byte *buffer, byte bufferSize) {
    for (byte i = 0; i < bufferSize; i++) {
        Serial.print(buffer[i] < 0x10 ? " 0" : " ");
        Serial.print(buffer[i], HEX);
    }
}