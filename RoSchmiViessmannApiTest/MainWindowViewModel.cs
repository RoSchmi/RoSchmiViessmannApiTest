using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System.Text;
using System.Text.Json;
using System.Windows.Input;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Net.Http;
using System.Windows;


namespace RoSchmiViessmannApiTest
{
    internal  sealed partial class MainWindowViewModel : ObservableObject
    {
        public MainWindowViewModel()
        {           
            Get_Authorization_Clicked_Command = new AsyncRelayCommand(GetAuthorizationResponse);
            Get_Access_Token_Clicked_Command = new AsyncRelayCommand(GetTokenResponse);        
            Copy_Url_to_Clipboard_Clicked_Command = new RelayCommand(CopyUrlToClipboard);
            Copy_Access_Token_to_Clipboard_Clicked_Command = new RelayCommand(CopyAccessTokenToClipboard);
            Copy_Refresh_Token_to_Clipboard_Clicked_Command = new RelayCommand(CopyRefreshTokenToClipboard);
            Create_New_Codeverifier_Clicked_Command = new RelayCommand(CreateNewCodeVerifier);
        }

        public IAsyncRelayCommand Get_Authorization_Clicked_Command { get; }
        public IAsyncRelayCommand Get_Access_Token_Clicked_Command { get; }   
        public ICommand Copy_Url_to_Clipboard_Clicked_Command { set; get; }
        public ICommand Copy_Access_Token_to_Clipboard_Clicked_Command { set; get; }
        public ICommand Copy_Refresh_Token_to_Clipboard_Clicked_Command { set; get; }
        public ICommand Create_New_Codeverifier_Clicked_Command { set; get; }


        private void CreateNewCodeVerifier() => Code_verifier = randomCodeVerifier(45);
        private void CopyUrlToClipboard() => Clipboard.SetText(RequestUrl);
        private void CopyAccessTokenToClipboard() => Clipboard.SetText(AccessToken);

        private void CopyRefreshTokenToClipboard() => Clipboard.SetText(RefreshToken);

        #region Task<string?> GetAuthorizationResponse()
        private async Task<string?> GetAuthorizationResponse()
        {
           
            AuthenticationCode = "";
            
            byte[] hashBytes;
            using (SHA256 mySHA256 = SHA256.Create())
            {
                hashBytes = mySHA256.ComputeHash(Encoding.UTF8.GetBytes(Code_verifier));

            }
            base64Url_Code_verifier = Base64UrlEncoder.Encode(hashBytes);
            code_challenge = base64Url_Code_verifier;

            // Create Query-String with parameters
            string queryString = $"client_id={Uri.EscapeDataString(Client_id)}" +
                $"&redirect_uri={Uri.EscapeDataString(redirect_uri)}" +
                $"&scope={Uri.EscapeDataString(AddRefreshToken ? scope_IoT_User_offline_access : scope_IoT_User)}" +
                $"&response_type={Uri.EscapeDataString(response_type)}" +
                $"&code_challenge_method={Uri.EscapeDataString(code_challenge_method)}" +
                $"&code_challenge={code_challenge}";

            System.Net.Http.HttpResponseMessage? response;
            string? content = null; ;

            using (var client = new HttpClient())
            {
                RequestUrl = $"{authorizeBaseUri}?{queryString}";
                response = await client.GetAsync(RequestUrl);
                content = await response.Content.ReadAsStringAsync();
            }

            return content;
        }

        #endregion

        #region GetTokenResponse()
        private async Task<string?> GetTokenResponse()
        {
            // Create Content-String for POST request
            string sendContentString = $"client_id={Uri.EscapeDataString(Client_id)}" +
                $"&redirect_uri={redirect_uri}" +
                $"&grant_type={Uri.EscapeDataString(grant_type)}" +
                $"&code_verifier={Uri.EscapeDataString(Code_verifier)}" +
                $"&code={Uri.EscapeDataString(AuthenticationCode)}";
  
            string encodedUrl = $"{tokenBaseUri}";
            HttpResponseMessage? responseMessage = null;
            string? responseContent = null;

            ViApiToken? viApiToken;

            using (var client = new HttpClient())
            {
                StringContent content = new  StringContent(sendContentString, Encoding.UTF8, "application/x-www-form-urlencoded") ;

                try
                {
                    var requestMessage = new HttpRequestMessage
                    {
                        Method = HttpMethod.Post,
                        Headers = { { "Host", "iam.viessmann.com"
                            } },
                        RequestUri = new Uri(tokenBaseUri),
                        Content = content
                    };           

                    responseMessage =  await client.SendAsync(requestMessage);
                    responseContent = await responseMessage.Content.ReadAsStringAsync();

                    viApiToken = JsonSerializer.Deserialize<ViApiToken>(responseContent);

                    AccessToken = viApiToken != null ? viApiToken.access_token : string.Empty;

                    RefreshToken = viApiToken != null ? viApiToken.refresh_token != null ? viApiToken.refresh_token : string.Empty : string.Empty;
                }
                catch (Exception e)
                {
                    string? theExceptionMessage = e.Message;
                };
            }
            return responseContent;
        }
        #endregion
 
        private static string randomCodeVerifier(int length)
        {
            // This is a quick and dirty function, not certain that it will always work properly

            // Restrict to length between 43 and 100
            length = length < 43 ? 43 : length >100 ? 100 : length ;
            // Create random Byte-Array
            byte[] randomBytes = new byte[length];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(randomBytes);
            }          
            return Base64UrlEncoder.Encode(randomBytes);
        }


        [ObservableProperty]
        private string? requestUrl;

        [ObservableProperty]
        private string? authenticationCode;

        [ObservableProperty]
        private string? accessToken;

        [ObservableProperty]
        private string? refreshToken;

        [ObservableProperty]
        private string client_id = "";

        [ObservableProperty]
        private string code_verifier = randomCodeVerifier(43); // between 43 and 128 Char

        [ObservableProperty]
        private bool addRefreshToken = false;

        private const string authorizeBaseUri = "https://iam.viessmann.com/idp/v3/authorize";
        private const string tokenBaseUri = "https://iam.viessmann.com/idp/v3/token";           
        private const string redirect_uri = "http://localhost:4200/";
        private const string scope_IoT_User = "IoT User";
        private const string scope_IoT_User_offline_access = "IoT User offline_access";
        private const string response_type = "code";
        private const string code_challenge_method = "S256";
        private const string grant_type = "authorization_code";

        private string? requestResult;
        private string code_challenge = "";

        private string? sha256_hashed_codeverifier;
        private string? base64Url_Code_verifier;
    }
}
