using IdentityModel.Client;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Security.Policy;
using System.Text;
using System.Data;
using System.IO;
using System.Reflection;

namespace UMPortalDevCheckout
{
    class Program
    {

        private const string ApplicationProxyUrl = "http://proxypdc.ahm.corp:9119";
        public static IServiceCollection services;
        public static IServiceProvider serviceProvider;
        public static List<ServerCheck> lstServerCheck;
        public const string AA = "AA";
        public static Settings settings = new Settings();
        static void Main(string[] args)
        {
            services = new ServiceCollection();
            //// Startup.cs finally :)
            Startup startup = new Startup();
            startup.ConfigureServices(services);
            serviceProvider = services.BuildServiceProvider();
            var idsvrSetting = new IdentityServerSetting();
           

            DataTable workTable = new DataTable("Results");


            var Configuration = serviceProvider.GetService<IConfigurationRoot>();

            Configuration.GetSection("IdentityServerSetting").Bind(idsvrSetting);
            Configuration.GetSection("Settings").Bind(settings);

            lstServerCheck = Configuration.GetSection("ServerChecks").Get<List<ServerCheck>>();
            try
            {
                CallHealthCheck(idsvrSetting).Wait();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"There was an exception: {ex.ToString()}");
            }
            Console.WriteLine("All servers processed.");
            Console.ReadLine();
        }


        public static async Task<string> CallHealthCheck(IdentityServerSetting idsvrcSetting)
        {
            //specify to use TLS 1.2 as default connection
            System.Net.ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;

            ServicePointManager.ServerCertificateValidationCallback += (o, c, ch, er) =>
            {
                return true;
            };
            var proxy = new WebProxy()
            {
                Address = new Uri("http://proxy.aetna.com:9119"),
                UseDefaultCredentials = false,

                // *** These creds are given to the proxy server, not the web server ***
                Credentials = new NetworkCredential(settings.ProxyUserName, settings.ProxyPwd)
            };

            var httpClientHandler = new HttpClientHandler()
            {
                //  Proxy = proxy,
                ServerCertificateCustomValidationCallback = (o, c, ch, er) =>
                 {
                     return true;
                 }

            };


            //var httpClientFactory = serviceProvider.GetService<IHttpClientFactory>();

            // get the http client
            //var client = new HttpClient();
            var client = new HttpClient(handler: httpClientHandler, disposeHandler: true);


            // discover endpoints from metadata
            var oidcDiscoveryResult = await DiscoveryClient.GetAsync(idsvrcSetting.IdentityServerUrl);
            if (oidcDiscoveryResult.IsError)
            {
                Console.WriteLine(oidcDiscoveryResult.Error);
                return oidcDiscoveryResult.Error;
            }

            //Console.WriteLine(tokenResponse.Json);
            //Console.WriteLine("\n\n");

            Dictionary<string, Result> allresults = new Dictionary<string, Result>();
            int i = 0;
            //  http://localhost:19641/api/HealthCheck/fileinfo
            foreach (ServerCheck chk in lstServerCheck)
            {
               
                if (chk.Type == "UMPortalWeb")
                {
                    // request token
                    var tokenClient = new TokenClient(oidcDiscoveryResult.TokenEndpoint, idsvrcSetting.APIClientId, idsvrcSetting.APIClientSecret);
                    var tokenResponse = await tokenClient.RequestClientCredentialsAsync(idsvrcSetting.ResourceAPIName);
                    if (tokenResponse.IsError)
                    {
                        Console.WriteLine(tokenResponse.Error);
                        throw new HttpRequestException(tokenResponse.Error);
                    }
                    else
                    {
                        client.SetBearerToken(tokenResponse.AccessToken);
                    }
                }

                if (chk.Type == "AAWebServices")
                {
                    client.SetBasicAuthentication(settings.AAWebservicesUserName, settings.AAWebservicesPwd);
                }


                //new datatable for each server;
                var tableResults = new DataTable();

                // Create the table definition
                tableResults.Columns.Add("Server");
                foreach (string strdll in chk.DLLFiles)
                {
                    tableResults.Columns.Add(new DataColumn(strdll));
                }
                foreach (string strconfig in chk.ConfigFiles)
                {
                    tableResults.Columns.Add(new DataColumn(strconfig));
                }

                foreach (string server in chk.Servers)
                {

                    var row = tableResults.NewRow();
                    row["Server"] = server;

                    int colnum = 0;
                    List<string> lstResults = new List<string>();

                    //Get the dll file info for all servers at the same time
                    string infoUrl = GetFileInfoUrl(server, chk.DLLFiles, chk.Type);
                    try
                    {
                        var response = await client.GetAsync(infoUrl);
                        if (!response.IsSuccessStatusCode)
                        {
                            Console.WriteLine(response.StatusCode);
                            throw new HttpRequestException(response.StatusCode.ToString());
                        }
                        else
                        {
                            var content = await response.Content.ReadAsStringAsync();
                            JArray result = JArray.Parse(content);

                            foreach (JObject item in result)
                            {
                                if (chk.Type == "UMPortal" || chk.Type == "UMPortalWeb")
                                {
                                    string name = item.GetValue("fileName").ToString();
                                    string creationTimeUTC = item.GetValue("creationTimeUTC").ToString();
                                    string lastModifiedTimeUTC = item.GetValue("lastModifiedTimeUTC").ToString();
                                    string assembleName = item.GetValue("assemblyName").ToString();

                                    row[++colnum] = name + ":" + lastModifiedTimeUTC + ":" + assembleName;
                                }
                                else
                                {
                                    string name = item.GetValue("FileName").ToString();
                                    string creationTimeUTC = item.GetValue("CreationTimeUTC").ToString();
                                    string lastModifiedTimeUTC = item.GetValue("LastModifiedTimeUTC").ToString();
                                    string assembleName = item.GetValue("AssemblyName").ToString();

                                    row[++colnum] = name + ":" + lastModifiedTimeUTC + ":" + assembleName;
                                }
                            }

                            //    Console.WriteLine(content);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.Message);
                    }
                    //Get the config files in the for loop
                    try
                    {
                        if (chk.ConfigFiles.Length > 0)
                    {
                        Dictionary<string, string> lstconfig = new Dictionary<string, string>();
                        foreach (string file in chk.ConfigFiles)
                        {
                            string fileUrl = GetFileUrl(server, file, chk.Type);
                            var responseFile = await client.GetAsync(fileUrl);
                            if (!responseFile.IsSuccessStatusCode)
                            {
                                Console.WriteLine(responseFile.StatusCode);
                                throw new HttpRequestException(responseFile.StatusCode.ToString());
                            }
                            else
                            {
                                var content = await responseFile.Content.ReadAsStringAsync();
                                row[++colnum] = content;
                             //   Console.WriteLine(content);
                            }
                        }
                    }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.Message);
                    }
                    tableResults.Rows.Add(row);

                }
                ExportDatatableToHtml(tableResults, chk.Name);
                
            }
            return "";
        }


        public static void ExportDatatableToHtml(DataTable dt, string name)
        {
            string tableStyle = @"<style>
                                        table {
                                          width: 100%;
                                          background-color: #FFFFFF;
                                          border-collapse: collapse;
                                          border-width: 1px;
                                          border-color: #7EA8F8;
                                          border-style: solid;
                                          color: #000000;
                                        }

                                        table td, table th {
                                          border-width: 1px;
                                          border-color: #7EA8F8;
                                          border-style: solid;
                                          padding: 5px;
                                        }

                                        table thead {
                                          background-color: #72BBDB;
                                        }
                                   </style>";

            StringBuilder strHTMLBuilder = new StringBuilder();
            strHTMLBuilder.Append("<html >");
            strHTMLBuilder.Append("<head>");
            strHTMLBuilder.Append(tableStyle);
            strHTMLBuilder.Append("</head>");
            strHTMLBuilder.Append("<body>");
            strHTMLBuilder.Append("<script type = 'text/javascript'> function toggle_visibility(id) { var e = document.getElementById(id); if (e.style.display == 'none') e.style.display = 'block'; else e.style.display = 'none';} </script>");
            strHTMLBuilder.Append("<table>");

            strHTMLBuilder.Append("<thead>");
            foreach (DataColumn myColumn in dt.Columns)
            {
                strHTMLBuilder.Append("<td>");
                strHTMLBuilder.Append(myColumn.ColumnName);
                strHTMLBuilder.Append("</td>");

            }
            strHTMLBuilder.Append("</thead>");

            int rowId = 0;
            foreach (DataRow myRow in dt.Rows)
            {
                rowId++;
                strHTMLBuilder.Append("<tr >");
                foreach (DataColumn myColumn in dt.Columns)
                {
                    var style = "";
                    if (dt.Rows[0][myColumn.ColumnName].ToString() != myRow[myColumn.ColumnName].ToString())
                    {
                       style = "bgcolor=#FF7A52";
                    }
                    strHTMLBuilder.Append("<td " + style + ">");
                    if (myColumn.ColumnName.Contains(".config") || myColumn.ColumnName.Contains(".json"))
                    {
                        string divId = "div" + rowId.ToString() + myColumn.Ordinal.ToString();
                        strHTMLBuilder.Append("<a href='' onclick=\"toggle_visibility('" + divId + "'); return false;\" > " + myColumn.ColumnName + "</a>" + "<div> <textarea readonly id='" + divId + "'style='border:none;display:none' rows='40' cols='40'>" + myRow[myColumn.ColumnName].ToString() + " </textarea> </div>");
                    }
                    else
                    {
                        strHTMLBuilder.Append(myRow[myColumn.ColumnName].ToString());
                    }
                    strHTMLBuilder.Append("</td>");

                }
                strHTMLBuilder.Append("</tr>");
            }

            //Close tags.  
            strHTMLBuilder.Append("</table>");
            strHTMLBuilder.Append("</body>");
            strHTMLBuilder.Append("</html>");

            System.IO.File.WriteAllText("report_" + name + "_" + DateTime.Now.ToFileTimeUtc().ToString() + ".html", strHTMLBuilder.ToString());

        }

        public static string GetFileInfoUrl(string server, string[] files, string type)
        {
            string url = "";
            switch (type)
            {
                case "AA":
                    url = server + "/aaprod/api/healthcheck/fileinfo?";
                    break;
                case "UMPortal":
                case "UMPortalWeb":
                    url = server + "/api/HealthCheck/fileinfo?";
                    break;
                case "AAWebApi":
                    url = server + "/AAWebAPI/api/healthcheck/fileinfo?";
                    break;
                case "AAWebServices":
                    url = server + "/aawebservices/api/HealthCheckWebService/fileinfo?";
                    break;
                case "AAViewApi":
                    url = server + "/AHM.AAView.AAProdWebAPI/api/healthcheck/fileinfo?";
                    break;
            }
            foreach (string f in files)
            {
                url = url + "files=" + f + "&";
            }
            return url;
        }

        public static string GetEnhancedInfo(string server, string type)
        {

            string url = server + "/api/HealthCheck/EnhancedInfo";

            return url;

        }

        public static string GetFileUrl(string server, string file, string type)
        {
            string url = "";
            switch (type)
            {
                case "AA":
                    url = server + "/aaprod/api/healthcheck/getfile?";
                    break;
                case "UMPortal":
                case "UMPortalWeb":
                    url = server + "/api/HealthCheck/getfile?";
                    break;
                case "AAWebApi":
                    url = server + "/AAWebAPI/api/healthcheck/getfile?";
                    break;
                case "AAWebServices":
                    url = server + "/aawebservices/api/HealthCheckWebService/getfile?";
                    break;
                case "AAViewApi":
                    url = server + "/AHM.AAView.AAProdWebAPI/api/healthcheck/getfile?";
                    break;
            }
            url = url + "file=" + file;
            return url;
        }


    }


    public class IdentityServerSetting
    {
        public string IdentityServerUrl { get; set; }
        public string APIClientId { get; set; }
        public string APIClientSecret { get; set; }
        public string IdentityServerScope { get; set; }
        public string ResourceAPIName { get; set; }

    }

    public class Settings
    {
        public string AAWebservicesUserName { get; set; }
        public string AAWebservicesPwd { get; set; }
        public string ProxyUserName { get; set; }
        public string ProxyPwd { get; set; }
    }

        public class ServerChecks
    {
        public ServerCheck[] Configs { get; set; }
    }
    public class ServerCheck
    {
        public string Type { get; set; }
        public string Name { get; set; }
        public string[] Servers { get; set; }
        public string[] DLLFiles { get; set; }
        public string[] ConfigFiles { get; set; }
    }

    public class Result
    {
        public List<string> dlls { get; set; }
        public Dictionary<string, string> configs { get; set; }
    }


    public class Startup
    {

        IConfigurationRoot Configuration { get; }
        public Startup()
        {
            var builder = new ConfigurationBuilder()
               .AddJsonFile("appsettings.json");

            Configuration = builder.Build();

        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddSingleton<IConfigurationRoot>(Configuration);

        }
    }
}
