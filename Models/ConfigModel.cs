using System;
using System.Collections.Generic;
using System.Text;

namespace Middleware.Target.TPlus_V12_3.Models
{
    public class ConfigModel
    {
        public string AppKey { get; set; }
        public string AppSecret { get; set; }
        public string OrgId { get; set; }
        public string HostUrl { get; set; }
        public string SecretUrl { get; set; }
    }
}
