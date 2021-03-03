using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Text;

namespace AddUserToGroupInDomain
{
    // Reference -
    // https://msdn.microsoft.com/en-us/library/ms676310(v=vs.85).aspx

    internal class Program
    {
        // Parent domain related
        private const string ParentDomain = "domain.com";
        private const string Username = @"domain\Administrator";
        private const string Password = "Pass99";

        // GC (Global Catalogue) related stuff
        private const string GcDcPath = "DC1.domain.com"; // because DC1 is set as GC
        private const int GcPort = 3268; // port 3269 using SSL

        // Child domain related
        private const string ChildDomain = "child.domain.com";
        private const string ChildUser = "viksaini";
        private const string ChildGroup = "Child Group";

        /* Goal achieved - 
          1. Find the user from GC
          2. Create DirectoryEntry object to child domain
          3. Add user to specific group                      
       */

        private static void Main()
        {
            WriteToConsole("Initiating process ...");
            Console.WriteLine();

            try
            {
                //const string bindString = "LDAP://domain.com/CN=TicketGroup,OU=Groups,DC=domain,DC=com";
                //const string newMember = "CN=Vikram Singh Saini,OU=Jersey,DC=domain,DC=com";
                //AddMemberToGroup(bindString, newMember);

                //AddUserToGroup(ChildUser, ChildGroup);

                //var userInfo = GetUserInfo("sn","Saini");
                //var userInfo = GetUserInfo("sAMAccountType", "viksaini");
                //var userInfo = GetUserInfo("userPrincipalName", "*");
                //var userInfo = GetUsers();
                //Console.WriteLine("Retrieved results-\n\n{0}", userInfo);

                if (SearchUserAndAddToGroup(GcDcPath, ChildDomain, ChildUser))
                {
                    WriteToConsole($"User {ChildUser} added to {ChildGroup} successfully.");
                }
            }
            catch (Exception e)
            {
                WriteToConsole(e.ToString(), true);
            }

            Console.WriteLine();
            WriteToConsole("Process completed.");
            Console.ReadKey();
        }

        /// <summary>
        /// Search for user in child domain.
        /// </summary>
        /// <param name="gcDomain">The domain controller which also play role of lobal catalog.</param>
        /// <param name="container">The distinguishedName of a container object.The container on the store to use as the root of the context. All queries are performed under this root, and all inserts are performed into this container.</param>
        /// <param name="sAMAccountName">The sAMAccountName of user to search.</param>
        /// <returns>Return true if user added to group successfuly else false.</returns>
        public static bool SearchUserAndAddToGroup(string gcDomain, string container, string sAMAccountName)
        {
            // Get distiniguishedName of child domain or container
            string childDistinguishedName; // DC=child,DC=domain.DC=com
            using (var childDe = new DirectoryEntry($"LDAP://{container}"))
            {
                childDistinguishedName = childDe.Properties["distinguishedName"].Value as string;
            }

            // While normal LDAP operations are serviced off of port 389 (port 636 using SSL),
            // the global catalog is serviced off of port 3268 (port 3269 using SSL).
            using (var parentContext = new PrincipalContext(ContextType.Domain, $"{gcDomain}:{GcPort}",
                    childDistinguishedName, ContextOptions.Negotiate, Username, Password))
            {
                var user = new UserPrincipal(parentContext) { SamAccountName = sAMAccountName };
                var principalSearcher = new PrincipalSearcher(user);

                var ps = principalSearcher.FindOne();
                var userPrincipal = ps as UserPrincipal;

                if (userPrincipal != null)
                {
                    AddUserToGroup(userPrincipal, gcDomain, childDistinguishedName, ChildGroup);
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Add user to group.
        /// </summary>
        /// <param name="user">The user which need to add to group.</param>
        /// <param name="gcDomain">The GC domain object.</param>
        /// <param name="container">The distinguished name of child domain.</param>
        /// <param name="groupName">The name of the group to which user will be added.</param>
        public static void AddUserToGroup(UserPrincipal user, string gcDomain, string container, string groupName)
        {
            // Bind to child domain 
            var childDe = new DirectoryEntry($"LDAP://{container}");

            using (childDe)
            {
                // Search group
                DirectoryEntry groupDe;
                using (var ds = new DirectorySearcher(childDe))
                {
                    ds.SizeLimit = 1; // Get me  only one record
                    ds.SearchScope = SearchScope.Subtree; // Search in base and sub-tree
                    ds.Filter = $"(&(objectClass=group)(name={groupName}))";
                    var result = ds.FindOne();
                    groupDe = result?.GetDirectoryEntry();
                }

                // Add user to group
                var userDe = user.GetUnderlyingObject() as DirectoryEntry;
                if (userDe != null)
                {
                    var userDePath = userDe.Path;
                    var isMember = groupDe != null && (bool)groupDe.Invoke("IsMember", userDePath);
                    if (!isMember)
                    {
                        groupDe?.Invoke("Add", userDePath);
                    }
                }
            }
        }
        
        /// <summary>
        /// Add member from one group in parent domain to another group in child domain.
        /// </summary>
        /// <param name="upn">The user from parent domain.</param>
        /// <param name="groupName">The name of the group in child domain.</param>
        public static void AddUserToGroup(string upn, string groupName)
        {
            var domainContext = GetPrincipalContext();
            WriteToConsole($"Searching for parent user {upn} in domain.com");

            // GET THE USER FROM DOMAIN domain.com
            using (var parentUser = UserPrincipal.FindByIdentity(domainContext, upn))
            {
                if (parentUser != null)
                {
                    WriteToConsole($"Parent user {parentUser.SamAccountName} was found.");
                    WriteToConsole($"Searching group {groupName} in {ChildDomain} ...");

                    // FIND THE GROUP IN DOMAIN child.domain.com
                    var childDomainContext = GetChildPrincipalContext();
                    var childGroupPrincipal = GroupPrincipal.FindByIdentity(childDomainContext, groupName);
                    using (childGroupPrincipal)
                    {
                        if (childGroupPrincipal != null)
                        {
                            WriteToConsole($"Child group {groupName} found in {ChildDomain}");

                            // CHECK TO MAKE SURE USER IS NOT IN THAT GROUP
                            if (!parentUser.IsMemberOf(childGroupPrincipal))
                            {
                                // Ref for server is unwilling to process request
                                // - http://stackoverflow.com/questions/13748970/server-is-unwilling-to-process-the-request-active-directory-add-user-via-c-s

                                var userDn = parentUser.DistinguishedName;
                                var userDnFullPath = $"LDAP://{ParentDomain}/{userDn}";

                                var childGroupDe = (DirectoryEntry)childGroupPrincipal.GetUnderlyingObject();
                                childGroupDe.Invoke("Add", userDnFullPath);
                                childGroupDe.CommitChanges();

                                WriteToConsole($"Parent user {parentUser.SamAccountName} added to child group {groupName} successfully.");
                            }
                            else
                            {
                                WriteToConsole($"User {parentUser.SamAccountName} is already member of  group {groupName}");
                            }
                        }
                        else
                        {
                            WriteToConsole($"Child group {groupName} not found in {ChildDomain}", true);
                        }
                    }

                }
            }
        }

        /// <summary>
        /// Add new member to group in domain.
        /// </summary>
        /// <param name="bindString">A valid ADsPath for a group container</param>
        /// <param name="newMember">The distinguished name of the member to be added to the group.</param>
        public static void AddMemberToGroup(string bindString, string newMember)
        {
            try
            {
                var ent = new DirectoryEntry(bindString);
                ent.Properties["member"].Add(newMember);
                ent.CommitChanges();

                Console.WriteLine("Member added to domain successfully!");
            }

            catch (Exception e)
            {
                Console.WriteLine("An error occurred.");
                Console.WriteLine("{0}", e.Message);
            }
        }

        /// <summary>
        /// Gets the parent principal context.
        /// </summary>
        /// <returns>Returns the PrincipalContext object</returns>
        public static PrincipalContext GetPrincipalContext()
        {
            WriteToConsole("Creating parent domain context");
            var principalContext = new PrincipalContext(ContextType.Domain, ParentDomain, Username, Password);
            return principalContext;
        }

        /// <summary>
        /// Gets the child principal context.
        /// </summary>
        /// <returns>Returns the PrincipalContext object</returns>
        public static PrincipalContext GetChildPrincipalContext()
        {
            WriteToConsole("Creating child domain context");
            var principalContext = new PrincipalContext(ContextType.Domain, ChildDomain, Username, Password);
            return principalContext;
        }

        /// <summary>
        /// Get users by searching global catalogue.
        /// </summary>
        /// <returns>Return string of users separated by comma.</returns>
        public static string GetUsers()
        {
            // While normal LDAP operations are serviced off of port 389 (port 636 using SSL),
            // the global catalog is serviced off of port 3268 (port 3269 using SSL).

            var appUsers = new List<string>();
            using (var pcxt = new PrincipalContext(ContextType.Domain, $"{GcDcPath}:{GcPort}", "DC=child,DC=domain,DC=com", ContextOptions.Negotiate, Username, Password))
            {
                var userPrincipal = new UserPrincipal(pcxt) { SamAccountName = ChildUser };
                var principalSearcher = new PrincipalSearcher(userPrincipal);

                appUsers.AddRange(from UserPrincipal up in principalSearcher.FindAll() select up.Name);
            }

            return string.Join(",", appUsers);

        }

        /// <summary>
        /// Get information about user from GC based on attribute and value.
        /// </summary>
        /// <param name="attributeName">The attribute name which will be used for searching.</param>
        /// <param name="attributeValue">The value of the attribute that will be used for search</param>
        /// <returns>Return information about user</returns>
        public static string GetUserInfo(string attributeName, string attributeValue)
        {
            var deRoot = new DirectoryEntry($"GC://{GcDcPath}", Username, Password);

            var sb = new StringBuilder();

            // Note the filter must be searching for a GC replicated attribute!
            // Sample - (sn=Saini*)
            var filter = $"({attributeName}={attributeValue})";

            var ds = new DirectorySearcher(deRoot, filter, null, SearchScope.Subtree);
            var src = ds.FindAll();

            using (src)
            {
                foreach (SearchResult sr in src)
                {
                    sb.AppendFormat("{0}\n", sr.Path);
                }
            }

            return sb.ToString();
        }

        /// <summary>
        /// Helper method to write message to console.
        /// </summary>
        /// <param name="msg">The message that need to be written to console.</param>
        /// <param name="isError">Whether to show the message in red color.</param>
        private static void WriteToConsole(string msg, bool isError = false)
        {
            if (isError)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(msg);
                Console.ResetColor();
            }
            else
            {
                Console.WriteLine(msg);
            }
        }
        
    }
}
