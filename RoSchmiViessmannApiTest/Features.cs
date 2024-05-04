using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RoSchmiViessmannApiTest
{
    // internal class Features


    public class Features
    {
        public FeatureDatum[] data { get; set; }
    }

    public class FeatureDatum
    {
        public string feature { get; set; }
        public string gatewayId { get; set; }
        public string deviceId { get; set; }
        public DateTime timestamp { get; set; }
        public bool isEnabled { get; set; }
        public bool isReady { get; set; }
        public int apiVersion { get; set; }
        public string uri { get; set; }
        public Properties properties { get; set; }
        public Commands commands { get; set; }
        public Deprecated deprecated { get; set; }
        public object[] components { get; set; }
    }

    public class Properties
    {
        public Entries entries { get; set; }
        public Value value { get; set; }
        public Status status { get; set; }
        public Enabled enabled { get; set; }
        public Hours hours { get; set; }
        public Starts starts { get; set; }
        public Active active { get; set; }
        public Shift shift { get; set; }
        public Slope slope { get; set; }
        public Demand demand { get; set; }
        public Temperature temperature { get; set; }
        public Name name { get; set; }
        public Type type { get; set; }
        public Start start { get; set; }
        public End end { get; set; }
    }

    public class Entries
    {
        public string type { get; set; }
        public object value { get; set; }
    }

    public class Value
    {
        public string type { get; set; }
        public object value { get; set; }
        public string unit { get; set; }
    }

    public class Status
    {
        public string type { get; set; }
        public string value { get; set; }
    }

    public class Enabled
    {
        public string type { get; set; }
        public string[] value { get; set; }
    }

    public class Hours
    {
        public string type { get; set; }
        public int value { get; set; }
        public string unit { get; set; }
    }

    public class Starts
    {
        public string type { get; set; }
        public int value { get; set; }
        public string unit { get; set; }
    }

    public class Active
    {
        public string type { get; set; }
        public bool value { get; set; }
    }

    public class Shift
    {
        public string type { get; set; }
        public int value { get; set; }
        public string unit { get; set; }
    }

    public class Slope
    {
        public string type { get; set; }
        public float value { get; set; }
        public string unit { get; set; }
    }

    public class Demand
    {
        public string type { get; set; }
        public string value { get; set; }
    }

    public class Temperature
    {
        public string type { get; set; }
        public int value { get; set; }
        public string unit { get; set; }
    }

    public class Name
    {
        public string type { get; set; }
        public string value { get; set; }
    }

    public class Type
    {
        public string type { get; set; }
        public string value { get; set; }
    }

    public class Start
    {
        public string type { get; set; }
        public string value { get; set; }
    }

    public class End
    {
        public string type { get; set; }
        public string value { get; set; }
    }

    public class Commands
    {
        public Setcurve setCurve { get; set; }
        public Setschedule setSchedule { get; set; }
        public Setmode setMode { get; set; }
        public Activate activate { get; set; }
        public Settemperature setTemperature { get; set; }
        public Deactivate deactivate { get; set; }
        public Setname setName { get; set; }
        public Settargettemperature setTargetTemperature { get; set; }
        public Changeenddate changeEndDate { get; set; }
        public Schedule schedule { get; set; }
        public Unschedule unschedule { get; set; }
    }

    public class Setcurve
    {
        public string uri { get; set; }
        public string name { get; set; }
        public bool isExecutable { get; set; }
        public Params _params { get; set; }
    }

    public class Params
    {
        public Slope1 slope { get; set; }
        public Shift1 shift { get; set; }
    }

    public class Slope1
    {
        public string type { get; set; }
        public bool required { get; set; }
        public Constraints constraints { get; set; }
    }

    public class Constraints
    {
        public float min { get; set; }
        public float max { get; set; }
        public float stepping { get; set; }
    }

    public class Shift1
    {
        public string type { get; set; }
        public bool required { get; set; }
        public Constraints1 constraints { get; set; }
    }

    public class Constraints1
    {
        public int min { get; set; }
        public int max { get; set; }
        public int stepping { get; set; }
    }

    public class Setschedule
    {
        public string uri { get; set; }
        public string name { get; set; }
        public bool isExecutable { get; set; }
        public Params1 _params { get; set; }
    }

    public class Params1
    {
        public Newschedule newSchedule { get; set; }
    }

    public class Newschedule
    {
        public string type { get; set; }
        public bool required { get; set; }
        public Constraints2 constraints { get; set; }
    }

    public class Constraints2
    {
        public string[] modes { get; set; }
        public int maxEntries { get; set; }
        public int resolution { get; set; }
        public string defaultMode { get; set; }
        public bool overlapAllowed { get; set; }
    }

    public class Setmode
    {
        public string uri { get; set; }
        public string name { get; set; }
        public bool isExecutable { get; set; }
        public Params2 _params { get; set; }
    }

    public class Params2
    {
        public Mode mode { get; set; }
    }

    public class Mode
    {
        public string type { get; set; }
        public bool required { get; set; }
        public Constraints3 constraints { get; set; }
    }

    public class Constraints3
    {
        public string[] _enum { get; set; }
    }

    public class Activate
    {
        public string uri { get; set; }
        public string name { get; set; }
        public bool isExecutable { get; set; }
        public Params3 _params { get; set; }
    }

    public class Params3
    {
        public Temperature1 temperature { get; set; }
    }

    public class Temperature1
    {
        public string type { get; set; }
        public bool required { get; set; }
        public Constraints4 constraints { get; set; }
    }

    public class Constraints4
    {
        public int min { get; set; }
        public int max { get; set; }
        public int stepping { get; set; }
    }

    public class Settemperature
    {
        public string uri { get; set; }
        public string name { get; set; }
        public bool isExecutable { get; set; }
        public Params4 _params { get; set; }
    }

    public class Params4
    {
        public Targettemperature targetTemperature { get; set; }
    }

    public class Targettemperature
    {
        public string type { get; set; }
        public bool required { get; set; }
        public Constraints5 constraints { get; set; }
    }

    public class Constraints5
    {
        public int min { get; set; }
        public int max { get; set; }
        public int stepping { get; set; }
    }

    public class Deactivate
    {
        public string uri { get; set; }
        public string name { get; set; }
        public bool isExecutable { get; set; }
        public Params5 _params { get; set; }
    }

    public class Params5
    {
    }

    public class Setname
    {
        public string uri { get; set; }
        public string name { get; set; }
        public bool isExecutable { get; set; }
        public Params6 _params { get; set; }
    }

    public class Params6
    {
        public Name1 name { get; set; }
    }

    public class Name1
    {
        public string type { get; set; }
        public bool required { get; set; }
        public Constraints6 constraints { get; set; }
    }

    public class Constraints6
    {
        public int minLength { get; set; }
        public int maxLength { get; set; }
    }

    public class Settargettemperature
    {
        public string uri { get; set; }
        public string name { get; set; }
        public bool isExecutable { get; set; }
        public Params7 _params { get; set; }
    }

    public class Params7
    {
        public Temperature2 temperature { get; set; }
    }

    public class Temperature2
    {
        public string type { get; set; }
        public bool required { get; set; }
        public Constraints7 constraints { get; set; }
    }

    public class Constraints7
    {
        public int min { get; set; }
        public int efficientLowerBorder { get; set; }
        public int efficientUpperBorder { get; set; }
        public int max { get; set; }
        public int stepping { get; set; }
    }

    public class Changeenddate
    {
        public string uri { get; set; }
        public string name { get; set; }
        public bool isExecutable { get; set; }
        public Params8 _params { get; set; }
    }

    public class Params8
    {
        public End1 end { get; set; }
    }

    public class End1
    {
        public string type { get; set; }
        public bool required { get; set; }
        public Constraints8 constraints { get; set; }
    }

    public class Constraints8
    {
        public string regEx { get; set; }
        public bool sameDayAllowed { get; set; }
    }

    public class Schedule
    {
        public string uri { get; set; }
        public string name { get; set; }
        public bool isExecutable { get; set; }
        public Params9 _params { get; set; }
    }

    public class Params9
    {
        public Start1 start { get; set; }
        public End2 end { get; set; }
    }

    public class Start1
    {
        public string type { get; set; }
        public bool required { get; set; }
        public Constraints9 constraints { get; set; }
    }

    public class Constraints9
    {
        public string regEx { get; set; }
    }

    public class End2
    {
        public string type { get; set; }
        public bool required { get; set; }
        public Constraints10 constraints { get; set; }
    }

    public class Constraints10
    {
        public string regEx { get; set; }
        public bool sameDayAllowed { get; set; }
    }

    public class Unschedule
    {
        public string uri { get; set; }
        public string name { get; set; }
        public bool isExecutable { get; set; }
        public Params10 _params { get; set; }
    }

    public class Params10
    {
    }

    public class Deprecated
    {
        public string removalDate { get; set; }
        public string info { get; set; }
    }


}
