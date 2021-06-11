using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CloudLAPSPortal.Models
{
    public class AuditEvent
    {
        public string UserPrincipalName { get; set; }
        public string Action { get; set; }
        public string ComputerName { get; set; }
        public DateTime CreatedOn { get; set; }
        public string Result { get; set; }
        public string Id { get; set; }
    }
}
