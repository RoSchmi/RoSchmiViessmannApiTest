using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Input;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Net.Http;
using System.Windows;
using System.Threading.Tasks;
using System.IO;
using System.Net;
using System.Security.Policy;
using Microsoft.VisualBasic;
using System.Threading;
using static System.Formats.Asn1.AsnWriter;
using System.Windows.Markup;
using static System.Net.WebRequestMethods;
using static System.Runtime.InteropServices.JavaScript.JSType;
using System.Diagnostics.Eventing.Reader;

namespace RoSchmiViessmannApiTest
{
    internal sealed class  MainWindowViewModel : ObservableObject
    {
        public MainWindowViewModel()
        {  
            Get_Authorization_Clicked_Command = new RelayCommand(GetAuthorization);
            Get_Authorization_Token_Clicked_Command = new RelayCommand(GetToken);
            Copy_Url_to_Clipboard_Clicked_Command = new RelayCommand(CopyUrlToClipboard);
            Copy_Token_to_Clipboard_Clicked_Command = new RelayCommand(CopyTokenToClipboard);
            Create_New_Codeverifier_Clicked_Command = new RelayCommand(CreateNewCodeVerifier);
        }

        
        public ICommand Get_Authorization_Clicked_Command { set; get; }
        public ICommand Get_Authorization_Token_Clicked_Command { set; get; }

        public ICommand Copy_Url_to_Clipboard_Clicked_Command { set; get; }

        public ICommand Copy_Token_to_Clipboard_Clicked_Command { set; get; }

        public ICommand Create_New_Codeverifier_Clicked_Command { set; get; }

        public string RequestUrl { get => requestUrl; set { _ = SetProperty(ref requestUrl, value); } }

        public string AuthenticationCode { get => authenticationCode; set { _ = SetProperty(ref authenticationCode, value); } }

        public string AuthenticationToken { get => authenticationToken; set { _ = SetProperty(ref authenticationToken, value); } }

        public string Code_verifier { get => code_verifier; set { _ = SetProperty(ref code_verifier, value); } }



        public string Client_id { get => client_id; set { _ = SetProperty(ref client_id, value); } }

        private string requestResult;

        private void CreateNewCodeVerifier()
        {
            Code_verifier = randomCodeVerifier(45);
        }

        private void GetAuthorization()
        {
            var thisresp = GetAuthorizationResponse();
        }

        private void CopyUrlToClipboard()
        {
            Clipboard.SetText(RequestUrl);
        }

        private void CopyTokenToClipboard()
        {
            Clipboard.SetText(AuthenticationToken);
        }
        private void GetToken()
        {
            
            var thisresp = GetTokenResponse();
        }
        private async Task<string> GetTokenResponse()
        {
            // Create Query-String with parameters
            string queryString = $"client_id={Uri.EscapeDataString(Client_id)}" +
                $"&redirect_uri={redirect_uri}" +
                $"&grant_type={Uri.EscapeDataString(grant_type)}" +
                $"&code_verifier={Uri.EscapeDataString(code_verifier)}" +
                $"&code={Uri.EscapeDataString(AuthenticationCode)}";

            System.Net.Http.HttpResponseMessage message = null;

            
            string encodedUrl = $"{tokenbaseUri}";
            HttpResponseMessage respMessage = null;
            string? responseContent;

            using (var client = new HttpClient())
            {
                StringContent content = new  StringContent(queryString, Encoding.UTF8, "application/x-www-form-urlencoded") ;

                try
                {
                    var requestMessage = new HttpRequestMessage
                    {
                        Method = HttpMethod.Post,
                        Headers = { { "Host", "iam.viessmann.com"
                            } },
                        RequestUri = new Uri(encodedUrl),
                        Content = content
                    };           

                 respMessage =  await client.SendAsync(requestMessage);
                 responseContent = await respMessage.Content.ReadAsStringAsync();

                    string[] contentArray = responseContent.Split(new char[] { '\"' });

                    AuthenticationToken = contentArray[1] == "access_token" ? contentArray[3] : string.Empty;              
                }
                catch (Exception e)
                {
                    string theMess = e.Message;
                };

            }


            /*
                using (var client = new HttpClient())
            {
                
               // string encodedUrl = $"{tokenbaseUri}?{queryString}";

                 // client.DefaultRequestHeaders.Add("Content-Type", "application/x-www-form-urlencoded");

                //RequestUrl = encodedUrl;

                var response = await client.PostAsync(encodedUrl, null);
                //var response = await client.GetAsync(encodedUrl);


                string content = await response.Content.ReadAsStringAsync();

                // Überprüfen Sie den Statuscode der Antwort
                
                //if (response.IsSuccessStatusCode)
                //{
                //    string result = await response.Content.ReadAsStringAsync();
                 //   Console.WriteLine($"Antwort: {result}");
                //}
                
                message = response;
                int dummy6 = 0;
            }
            */
            return respMessage.Content.ToString();

            //  return message.Content.ToString();

        }


        private async Task<string> GetAuthorizationResponse()
        {
            
            AuthenticationCode = "";
            byte[] hashBytes;
            using (SHA256 mySHA256 = SHA256.Create())
            {
                hashBytes = mySHA256.ComputeHash(Encoding.UTF8.GetBytes(code_verifier));
                
            }
            base64Url_Code_verifier = Base64UrlEncoder.Encode(hashBytes);
            code_challenge = base64Url_Code_verifier;

            // Create Query-String with parameters
            string queryString=$"client_id={Uri.EscapeDataString(Client_id)}" +
                $"&redirect_uri={Uri.EscapeDataString(redirect_uri)}" +
                $"&scope={Uri.EscapeDataString(scope)}" +
                $"&response_type={Uri.EscapeDataString(response_type)}" +
                $"&code_challenge_method={Uri.EscapeDataString(code_challenge_method)}" +
                $"&code_challenge={code_challenge}";
           

            System.Net.Http.HttpResponseMessage message = null;

            using (var client = new HttpClient())
            {
                string encodedUrl = $"{authorizebaseUri}?{queryString}";
                     
                RequestUrl = encodedUrl;

                var response = await client.GetAsync(encodedUrl);

                string content = await response.Content.ReadAsStringAsync();

                // Überprüfen Sie den Statuscode der Antwort
                /*
                if (response.IsSuccessStatusCode)
                {
                    string result = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"Antwort: {result}");
                }
                */
                message = response;
                int dummy6 = 0;
            }

            return message.Content.ToString();
        }
        
            /*
            IncrementCounter();
            byte[] hashBytes;
            using (SHA256 mySHA256 = SHA256.Create())
            {
                hashBytes = mySHA256.ComputeHash(Encoding.UTF8.GetBytes(code_verifier));
                int dummy0 = 0;
            }     
            base64Url_Code_verifier = Base64UrlEncoder.Encode(hashBytes);
            code_challenge = base64Url_Code_verifier;

            // Erstelle den Query-String mit den Parametern
            string queryString = $"client_id={Uri.EscapeDataString(client_id)}" +
                $"&redirect_uri={Uri.EscapeDataString(redirect_uri)}" +
                $"&scope ={Uri.EscapeDataString(scope)}" +
                $"&response_type ={Uri.EscapeDataString(response_type)}" +
                $"&code_challenge_method = {Uri.EscapeDataString(code_challence_method)}" +
                $"&code_challenge = {Uri.EscapeDataString(code_challenge)}";

             */




            //HttpClient httpClient = httpClientFactory.CreateClient(Constants.DefaultHttpClientName);
            /*
            using (var client = new HttpClient())
            {
                string encodedUrl = $"{baseUri}?{queryString}";
                int dummy2 = 0;

                string responseContent = await httpResponseMessage.EnsureSuccessStatusCode().Content.ReadAsStringAsync(cancellationToken);

                //HttpResponseMessage response = await client.GetAsync(encodedUrl
                //
                HttpResponseMessage response = client.   (encodedUrl);

                // Überprüfen Sie den Statuscode der Antwort
                if (response.IsSuccessStatusCode)
                {
                    string result = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"Antwort: {result}");
                }
            }
            */

                int dummy1 = 0;


        /*
        static async Task getResponse()
        {
            using (var client = new HttpClient())
            {
                string encodedUrl = $"{baseUri}?{queryString}";
                int dummy2 = 0;

                //HttpResponseMessage response = await client.GetAsync(encodedUrl
                //
                HttpResponseMessage response = client.GetAsync(encodedUrl);

                // Überprüfen Sie den Statuscode der Antwort
                if (response.IsSuccessStatusCode)
                {
                    string result = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"Antwort: {result}");
                }
            }

        }
        */
        private static string randomCodeVerifier(int length)
        {
            // This is a quick and dirty function, not certain that it will work properly

            // Onlx Length between 43 and 100
            length = length < 43 ? 43 : length >100 ? 100 : length ;
            // Erzeuge einen zufälligen Byte-Array
            byte[] randomBytes = new byte[length];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(randomBytes);
            }          
            return Base64UrlEncoder.Encode(randomBytes);
        }

   
        private string requestUrl;

        private string authenticationCode;

        private string authenticationToken;

        
        private string client_id = ""; 

        private string code_verifier = randomCodeVerifier(43); // between 43 and 128 Char


        private const string authorizebaseUri = "https://iam.viessmann.com/idp/v3/authorize";

        private const string tokenbaseUri = "https://iam.viessmann.com/idp/v3/token";
          
        
        private const string redirect_uri = "http://localhost:4200/";
        private const string scope = "IoT User";
        private const string response_type = "code";
        private const string code_challenge_method = "S256";

        private const string grant_type = "authorization_code";

        private string code_challenge = "";

        private string sha256_hashed_codeverifier;
        private string base64Url_Code_verifier;

    }
}
