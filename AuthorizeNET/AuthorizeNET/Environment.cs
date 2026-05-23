namespace AuthorizeNet
{
	/*================================================================================
    * 
    * Determines the target environment to post API requests.
    *
    * SANDBOX should be used for testing. Transactions submitted to the sandbox 
    * will not result in an actual card payment. Instead, the sandbox simulates 
    * the response. Use the Testing Guide to generate specific gateway responses.
    *
    * PRODUCTION connects to the production gateway environment.
    *
    *===============================================================================*/
	public class Environment
	{
		public static readonly Environment SANDBOX = new Environment("https://test.authorize.net", "https://apitest.authorize.net", "https://test.authorize.net");
		public static readonly Environment PRODUCTION = new Environment("https://secure2.authorize.net", "https://api2.authorize.net", "https://cardpresent.authorize.net");
		public static readonly Environment LOCAL_VM = new Environment(null, null, null);
		public static readonly Environment HOSTED_VM = new Environment(null, null, null);
		public static Environment CUSTOM = new Environment(null, null, null);
		
		/// <summary>
		/// Gets whether to use HTTP proxy. Immutable - set via constructor for thread safety.
		/// </summary>
		public bool HttpUseProxy { get; }
		
		/// <summary>
		/// Gets the HTTPS proxy username. Immutable - set via constructor for thread safety.
		/// </summary>
		public string HttpsProxyUsername { get; }
		
		/// <summary>
		/// Gets the HTTPS proxy password. Immutable - set via constructor for thread safety.
		/// </summary>
		public string HttpsProxyPassword { get; }
		
		/// <summary>
		/// Gets the HTTP proxy host. Immutable - set via constructor for thread safety.
		/// </summary>
		public string HttpProxyHost { get; }
		
		/// <summary>
		/// Gets the HTTP proxy port. Immutable - set via constructor for thread safety.
		/// </summary>
		public int HttpProxyPort { get; }
		

	public Environment(string baseUrl, string xmlBaseUrl, string cardPresentUrl)
		: this(baseUrl, xmlBaseUrl, cardPresentUrl, false, null, 0, null, null)
	{
	}

	/// <summary>
	/// Creates a new Environment with the specified URLs and optional proxy settings.
	/// </summary>
	/// <param name="baseUrl">Base URL</param>
	/// <param name="xmlBaseUrl">XML base URL</param>
	/// <param name="cardPresentUrl">Card present URL</param>
	/// <param name="httpUseProxy">Whether to use HTTP proxy</param>
	/// <param name="proxyHost">Proxy host address</param>
	/// <param name="proxyPort">Proxy port number</param>
	/// <param name="proxyUsername">Proxy username for authentication</param>
	/// <param name="proxyPassword">Proxy password for authentication</param>
	public Environment(string baseUrl, string xmlBaseUrl, string cardPresentUrl,
					  bool httpUseProxy = false, string proxyHost = null, int proxyPort = 0,
					  string proxyUsername = null, string proxyPassword = null)
	{
		BaseUrl = baseUrl;
		XmlBaseUrl = xmlBaseUrl;
		CardPresentUrl = cardPresentUrl;
		HttpUseProxy = httpUseProxy;
		HttpProxyHost = proxyHost;
		HttpProxyPort = proxyPort;
		HttpsProxyUsername = proxyUsername;
		HttpsProxyPassword = proxyPassword;
	}

		/// <summary>
		/// Gets the base url
		/// </summary>
		public string BaseUrl { get; private set; }

		/// <summary>
		/// Gets the xml base url
		/// </summary>
		public string XmlBaseUrl { get; private set; }

		/// <summary>
		/// Gets the card present url
		/// </summary>
		public string CardPresentUrl { get; private set; }

		/// <summary>
		/// Create a custom environment with the specified base url
		/// </summary>
		/// <param name="baseUrl">Base url</param>
		/// <param name="xmlBaseUrl">Xml base url</param>
		/// <returns>The custom environment</returns>
		public static Environment createEnvironment(string baseUrl, string xmlBaseUrl)
		{

			return createEnvironment(baseUrl, xmlBaseUrl, null);
		}


	/// <summary>
	/// Create a custom environment with the specified base url
	/// </summary>
	/// <param name="baseUrl">Base url</param>
	/// <param name="xmlBaseUrl">Xml base url</param>
	/// <param name="cardPresentUrl">Card present url</param>
	/// <returns>The custom environment</returns>
	public static Environment createEnvironment(string baseUrl, string xmlBaseUrl, string cardPresentUrl)
	{
		return new Environment(baseUrl, xmlBaseUrl, cardPresentUrl);
	}

		/// <summary>
		/// Reads an integer value from the environment
		/// </summary>
		/// <param name="propertyName">Name of the int property to read</param>
		/// <returns>Integer property value</returns>
		public static int getIntProperty(string propertyName)
		{
			int value = 0;
			var stringValue = GetProperty(propertyName);
			if (!string.IsNullOrWhiteSpace(stringValue))
			{
				int.TryParse(stringValue.Trim(), out value);
			}

			return value;
		}

		/// <summary>
		/// Reads a boolean value from the environment
		/// </summary>
		/// <param name="propertyName">Name of the boolean property to read</param>
		/// <returns>Boolean property value</returns>
		public static bool getBooleanProperty(string propertyName)
		{
			var value = false;
			var stringValue = GetProperty(propertyName);
			if (!string.IsNullOrWhiteSpace(stringValue))
			{
				bool.TryParse(stringValue.Trim(), out value);
			}

			return value;
		}

		/// <summary>
		/// Reads the value from the environment 
		/// </summary>
		/// <param name="propertyName">Name of the property to read</param>
		/// <returns>String property value</returns>
		public static string GetProperty(string propertyName)
		{
			return System.Environment.GetEnvironmentVariable(propertyName);
		}
	}
}
