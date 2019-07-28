namespace WatsonTcp
{
    using System;
    using System.IO;
    using System.Net.Sockets;
    using System.Security.Authentication;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using WatsonTcp.Message;

    /// <summary>
    /// Watson TCP client, with or without SSL.
    /// </summary>
    public class WatsonTcpClient : IDisposable
    {
        #region Public-Members

        /// <summary>
        /// Enable or disable full reading of input streams.  When enabled, use MessageReceived.  When disabled, use StreamReceived.
        /// </summary>
        public bool ReadDataStream = true;

        /// <summary>
        /// Buffer size to use when reading input and output streams.  Default is 65536.
        /// </summary>
        public int ReadStreamBufferSize
        {
            get => _ReadStreamBufferSize;
            set
            {
                if (value < 1)
                {
                    throw new ArgumentException("Read stream buffer size must be greater than zero.");
                }

                _ReadStreamBufferSize = value;
            }
        }

        /// <summary>
        /// Enable or disable console debugging.
        /// </summary>
        public bool Debug
        {
            get => Common._Debug;
            set => Common._Debug = value;
        }

        /// <summary>
        /// Function called when authentication is requested from the server.  Expects the 16-byte preshared key.
        /// </summary>
        public Func<string> AuthenticationRequested = null;

        /// <summary>
        /// Function called when authentication has succeeded.  Expects a response of 'true'.
        /// </summary>
        public Func<bool> AuthenticationSucceeded = null;

        /// <summary>
        /// Function called when authentication has failed.  Expects a response of 'true'.
        /// </summary>
        public Func<bool> AuthenticationFailure = null;

        /// <summary>
        /// Function called when a message is received.
        /// A byte array containing the message data is passed to this function.
        /// It is expected that 'true' will be returned.
        /// </summary>
        public Func<byte[], bool> MessageReceived = null;

        /// <summary>
        /// Method to call when a message is received from a client.
        /// The IP:port is passed to this method as a string, along with a long indicating the number of bytes to read from the stream.
        /// It is expected that the method will return true.
        /// </summary>
        public Func<long, Stream, bool> StreamReceived = null;

        /// <summary>
        /// Function called when the client successfully connects to the server.
        /// It is expected that 'true' will be returned.
        /// </summary>
        public Func<bool> ServerConnected = null;

        /// <summary>
        /// Function called when the client disconnects from the server.
        /// It is expected that 'true' will be returned.
        /// </summary>
        public Func<bool> ServerDisconnected = null;

        /// <summary>
        /// Enable acceptance of SSL certificates from the server that cannot be validated.
        /// </summary>
        public bool AcceptInvalidCertificates = true;

        /// <summary>
        /// Require mutual authentication between the server and this client.
        /// </summary>
        public bool MutuallyAuthenticate
        {
            get => _MutuallyAuthenticate;
            set
            {
                if (_SslCertificate == null && value)
                {
                    throw new ArgumentNullException("Certificate must be set if you want to Mutually Authenticate");
                }

                _MutuallyAuthenticate = value;
            }
        }

        /// <summary>
        /// Indicates whether or not the client is connected to the server.
        /// </summary>
        public bool Connected { get; private set; }

        #endregion

        #region Private-Members

        private bool _Disposed = false;
        private int _ReadStreamBufferSize = 65536;
        private readonly Mode _Mode;
        private readonly string _ServerIp;
        private readonly int _ServerPort;
        private ClientMetadata _Server;

        private readonly X509Certificate2 _SslCertificate;
        private readonly X509Certificate2Collection _SslCertificateCollection;

        private CancellationTokenSource _TokenSource;
        private CancellationToken _Token;

        private bool _MutuallyAuthenticate;

        #endregion

        #region Constructors-and-Factories

        /// <summary>
        /// Initialize the Watson TCP client without SSL.  Call Start() afterward to connect to the server.
        /// </summary>
        /// <param name="serverIp">The IP address or hostname of the server.</param>
        /// <param name="serverPort">The TCP port on which the server is listening.</param>
        public WatsonTcpClient(
            string serverIp,
            int serverPort)
            : this(Mode.Tcp, serverIp, serverPort, null)
        {
        }

        /// <summary>
        /// Initialize the Watson TCP client with SSL.  Call Start() afterward to connect to the server.
        /// </summary>
        /// <param name="serverIp">The IP address or hostname of the server.</param>
        /// <param name="serverPort">The TCP port on which the server is listening.</param>
        /// <param name="pfxCertFile">The file containing the SSL certificate.</param>
        /// <param name="pfxCertPass">The password for the SSL certificate.</param>
        public WatsonTcpClient(
            string serverIp,
            int serverPort,
            string pfxCertFile,
            string pfxCertPass)
            : this(Mode.Ssl, serverIp, serverPort, String.IsNullOrEmpty(pfxCertPass) ? new X509Certificate2(pfxCertFile) : new X509Certificate2(pfxCertFile, pfxCertPass))
        {
        }

        /// <summary>
        /// Initialize the Watson TCP client with SSL.  Call Start() afterward to connect to the server.
        /// </summary>
        /// <param name="mode">If using TCP or SSL.</param>
        /// <param name="serverIp">The IP address or hostname of the server.</param>
        /// <param name="serverPort">The TCP port on which the server is listening.</param>
        /// <param name="certificate">The certificate to use, if using SSL.</param>
        public WatsonTcpClient(
            Mode mode,
            string serverIp,
            int serverPort,
            X509Certificate2 certificate)
        {
            if (String.IsNullOrEmpty(serverIp))
            {
                throw new ArgumentNullException(nameof(serverIp));
            }

            if (serverPort < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(serverPort));
            }

            _Mode = mode;
            _ServerIp = serverIp;
            _ServerPort = serverPort;

            if (_Mode == Mode.Ssl && certificate != null)
            {
                _SslCertificate = certificate;

                _SslCertificateCollection = new X509Certificate2Collection
                {
                    _SslCertificate,
                };
            }
        }

        #endregion

        #region Public-Methods

        /// <summary>
        /// Tear down the client and dispose of background workers.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Start the client and establish a connection to the server.
        /// </summary>
        public void Start()
        {
            TcpClient client = new TcpClient();
            IAsyncResult asyncResult = null;
            WaitHandle waitHandle = null;

            if (_Mode == Mode.Tcp)
            {
                Common.Log("Watson TCP client connecting to " + _ServerIp + ":" + _ServerPort);
            }
            else if (_Mode == Mode.Ssl)
            {
                Common.Log("Watson TCP client connecting with SSL to " + _ServerIp + ":" + _ServerPort);
            }

            client.LingerState = new LingerOption(true, 0);
            asyncResult = client.BeginConnect(_ServerIp, _ServerPort, null, null);
            waitHandle = asyncResult.AsyncWaitHandle;

            try
            {
                if (!asyncResult.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(5), false))
                {
                    client.Close();
                    throw new TimeoutException("Timeout connecting to " + _ServerIp + ":" + _ServerPort);
                }

                client.EndConnect(asyncResult);

                _Server = new ClientMetadata(client, _Mode, AcceptInvalidCertificates);
                if (_Mode == Mode.Ssl)
                {
                    _Server.SslStream.AuthenticateAsClient(_ServerIp, _SslCertificateCollection, SslProtocols.Tls12, !AcceptInvalidCertificates);

                    if (!_Server.SslStream.IsEncrypted)
                    {
                        throw new AuthenticationException("Stream is not encrypted");
                    }

                    if (!_Server.SslStream.IsAuthenticated)
                    {
                        throw new AuthenticationException("Stream is not authenticated");
                    }

                    if (MutuallyAuthenticate && !_Server.SslStream.IsMutuallyAuthenticated)
                    {
                        throw new AuthenticationException("Mutual authentication failed");
                    }
                }

                Connected = true;
            }
            catch
            {
                throw;
            }
            finally
            {
                waitHandle.Close();
            }

            if (ServerConnected != null)
            {
                Task.Run(() => ServerConnected());
            }

            _TokenSource = new CancellationTokenSource();
            _Token = _TokenSource.Token;
            Task.Run(async () => await DataReceiver(_Token), _Token);
        }

        /// <summary>
        /// Send a pre-shared key to the server to authenticate.
        /// </summary>
        /// <param name="presharedKey">Up to 16-character string.</param>
        public void Authenticate(string presharedKey)
        {
            if (String.IsNullOrEmpty(presharedKey))
            {
                throw new ArgumentNullException(nameof(presharedKey));
            }

            if (presharedKey.Length != 16)
            {
                throw new ArgumentException("Preshared key length must be 16 bytes.");
            }

            presharedKey = presharedKey.PadRight(16, ' ');

            using (MemoryStream ms = new MemoryStream())
            {
                WatsonMessage msg = new WatsonMessage(MessageStatus.AuthRequested, 0, null)
                {
                    PresharedKey = Encoding.UTF8.GetBytes(presharedKey)
                };

                _Server.MessageWrite(msg, _ReadStreamBufferSize);
            }
        }

        /// <summary>
        /// Send data to the server.
        /// </summary>
        /// <param name="data">Byte array containing data.</param>
        /// <returns>Boolean indicating if the message was sent successfully.</returns>
        public bool Send(byte[] data)
        {
            return _Server.MessageWrite(MessageStatus.Normal, data, _ReadStreamBufferSize);
        }

        /// <summary>
        /// Send data to the server using a stream.
        /// </summary>
        /// <param name="contentLength">The number of bytes in the stream.</param>
        /// <param name="stream">The stream containing the data.</param>
        /// <returns>Boolean indicating if the message was sent successfully.</returns>
        public bool Send(long contentLength, Stream stream)
        {
            WatsonMessage msg = new WatsonMessage(MessageStatus.Normal, contentLength, stream);
            return _Server.MessageWrite(msg, _ReadStreamBufferSize);
        }

        /// <summary>
        /// Send data to the server asynchronously.
        /// </summary>
        /// <param name="data">Byte array containing data.</param>
        /// <returns>Task with Boolean indicating if the message was sent successfully.</returns>
        public async Task<bool> SendAsync(byte[] data)
        {
            return await _Server.MessageWriteAsync(MessageStatus.Normal, data, _ReadStreamBufferSize);
        }

        /// <summary>
        /// Send data to the server from a stream asynchronously.
        /// </summary>
        /// <param name="contentLength">The number of bytes to send.</param>
        /// <param name="stream">The stream containing the data.</param>
        /// <returns>Task with Boolean indicating if the message was sent successfully.</returns>
        public async Task<bool> SendAsync(long contentLength, Stream stream)
        {
            WatsonMessage msg = new WatsonMessage(MessageStatus.Normal, contentLength, stream);
            return await _Server.MessageWriteAsync(msg, _ReadStreamBufferSize);
        }

        #endregion

        #region Protected-Methods

        protected virtual void Dispose(bool disposing)
        {
            if (_Disposed)
            {
                return;
            }

            if (disposing)
            {
                _TokenSource.Cancel();
                _TokenSource.Dispose();

                _Server.Dispose();

                Connected = false;
            }

            _Disposed = true;
        }

        #endregion

        #region Private-Methods

        private async Task DataReceiver(CancellationToken? cancelToken = null)
        {
            try
            {
                #region Wait-for-Data

                while (true)
                {
                    cancelToken?.ThrowIfCancellationRequested();

                    #region Check-Connection

                    if (_Server.TcpClient == null)
                    {
                        Common.Log("*** DataReceiver null TCP interface detected, disconnection or close assumed");
                        break;
                    }

                    if (!_Server.TcpClient.Connected)
                    {
                        Common.Log("*** DataReceiver server disconnected");
                        break;
                    }

                    if (_Server.SslStream != null && !_Server.SslStream.CanRead)
                    {
                        Common.Log("*** DataReceiver cannot read from SSL stream");
                        break;
                    }

                    #endregion

                    #region Read-Message-and-Handle

                    WatsonMessage msg = null;

                    _Server.ReadLock.Wait(1);

                    try
                    {
                        msg = await _Server.MessageReadAsync(ReadDataStream);
                    }
                    finally
                    {
                        _Server.ReadLock.Release();
                    }

                    if (msg == null)
                    {
                        await Task.Delay(30);
                        continue;
                    }

                    if (msg.Status == MessageStatus.AuthSuccess)
                    {
                        Common.Log("DataReceiver successfully authenticated");
                        AuthenticationSucceeded?.Invoke();
                        continue;
                    }
                    else if (msg.Status == MessageStatus.AuthFailure)
                    {
                        Common.Log("DataReceiver authentication failed, please authenticate using pre-shared key");
                        AuthenticationFailure?.Invoke();
                        continue;
                    }

                    if (msg.Status == MessageStatus.AuthRequired)
                    {
                        Common.Log("DataReceiver authentication required, please authenticate using pre-shared key");
                        if (AuthenticationRequested != null)
                        {
                            string psk = AuthenticationRequested();
                            if (!String.IsNullOrEmpty(psk))
                            {
                                Authenticate(psk);
                            }
                        }

                        continue;
                    }

                    if (ReadDataStream)
                    {
                        if (MessageReceived != null)
                        {
                            Task<bool> unawaited = Task.Run(() => MessageReceived(msg.Data));
                        }
                    }
                    else
                    {
                        StreamReceived?.Invoke(msg.ContentLength, msg.DataStream);
                    }

                    #endregion
                }

                #endregion
            }
            catch (Exception e)
            {
                Common.Log("*** DataReceiver server disconnected unexpectedly");
                Common.Log(Common.SerializeJson(e));
            }
            finally
            {
                Connected = false;
                ServerDisconnected?.Invoke();
                _Server.Dispose();
            }
        }

        #endregion
    }
}
