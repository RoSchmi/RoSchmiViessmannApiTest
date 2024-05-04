using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RoSchmiViessmannApiTest
{
    public class UserIdentity
    {
        public string id { get; set; }
        public string loginId { get; set; }
        public string userState { get; set; }
        public string gender { get; set; }
        public IdName name { get; set; }
        public IdAddress address { get; set; }
        public IdContacts contacts { get; set; }
        public IdProperty1[] properties { get; set; }
        public bool isCeo { get; set; }
        public string languageCode { get; set; }
        public string locale { get; set; }
        public bool isLite { get; set; }
    }

    public class IdName
    {
        public string firstName { get; set; }
        public string familyName { get; set; }
    }

    public class IdAddress
    {
        public string postalCode { get; set; }
        public string city { get; set; }
        public string street { get; set; }
        public string houseNumber { get; set; }
        public string countryCode { get; set; }
    }

    public class IdContacts
    {
        public string telephone { get; set; }
        public string mobile { get; set; }
        public string email { get; set; }
    }

    public class IdProperty1
    {
        public string name { get; set; }
        public string value { get; set; }
    }

}
