using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Intrinsics.X86;
using System.Text;
using System.Threading.Tasks;

namespace RoSchmiViessmannApiTest
{
    // How to create the right Classes
    //
    // Use Visual Studio 2022 to automatically generate the class you need:
    // 1) Copy the JSON that you need to deserialize.
    // 2) Create a class file and delete the template code.
    // 3) Choose Edit (Bearbeiten) > Paste Special (Inhalte einfügen) > Paste JSON as Classes (JSON als Klassen einfügen).
    // The result is a class that you can use for your deserialization target.

    public class Installations
    {
        public  Cursor cursor { get; set; }
        

        public Datum[] data { get; set; }
    }

    public class Cursor
    {
        public string next { get; set; }
    }


    public class Datum
    {
        public int id { get; set; }
        public string description { get; set; }
        public Address address { get; set; }
        public Gateway[] gateways { get; set; }
        public DateTime registeredAt { get; set; }
        public DateTime updatedAt { get; set; }
        public string aggregatedStatus { get; set; }
        public object servicedBy { get; set; }
        public object heatingType { get; set; }
        public bool ownedByMaintainer { get; set; }
        public bool endUserWlanCommissioned { get; set; }
        public bool withoutViCareUser { get; set; }
        public string installationType { get; set; }
        public object buildingName { get; set; }
        public object buildingEmail { get; set; }
        public object buildingPhone { get; set; }
        public string accessLevel { get; set; }
        public string ownershipType { get; set; }
    }


    public class Address
    {
        public string street { get; set; }
        public string houseNumber { get; set; }
        public string zip { get; set; }
        public string city { get; set; }
        public object region { get; set; }
        public string country { get; set; }
        public object phoneNumber { get; set; }
        public object faxNumber { get; set; }
        public Geolocation geolocation { get; set; }
    }

    public class Geolocation
    {
        public float latitude { get; set; }
        public float longitude { get; set; }
        public string timeZone { get; set; }
    }

    public class Gateway
    {
        public string serial { get; set; }
        public string version { get; set; }
        public int firmwareUpdateFailureCounter { get; set; }
        public bool autoUpdate { get; set; }
        public DateTime createdAt { get; set; }
        public DateTime producedAt { get; set; }
        public DateTime lastStatusChangedAt { get; set; }
        public string aggregatedStatus { get; set; }
        public string targetRealm { get; set; }
        public string gatewayType { get; set; }
        public int installationId { get; set; }
        public DateTime registeredAt { get; set; }
        public object description { get; set; }
        public bool otaOngoing { get; set; }
        public Device[] devices { get; set; }
    }

    public class Device
    {
        public string gatewaySerial { get; set; }
        public string id { get; set; }
        public string boilerSerial { get; set; }
        public string boilerSerialEditor { get; set; }
        public string bmuSerial { get; set; }
        public string bmuSerialEditor { get; set; }
        public DateTime createdAt { get; set; }
        public DateTime editedAt { get; set; }
        public string modelId { get; set; }
        public string status { get; set; }
        public string deviceType { get; set; }
        public string[] roles { get; set; }
        public bool isBoilerSerialEditable { get; set; }
    }

}

