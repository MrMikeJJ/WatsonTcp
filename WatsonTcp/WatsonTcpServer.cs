namespace WatsonTcp
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Sockets;
    using System.Security.Authentication;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using WatsonTcp.Message;

    /// <summary>
    /// Watson TCP server, with or without SSL.
    /// </summary>
    public class WatsonTcpServer : IDisposable
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
        /// Permitted IP addresses.
        /// </summary>
        public List<string> PermittedIPs = null;

        /// <summary>
        /// Method to call when a client connects to the server.
        /// The IP:port is passed to this method as a string, and it is expected that the method will return true.
        /// </summary>
        public Func<string, bool> ClientConnected = null;

        /// <summary>
        /// Method to call when a client disconnects from the server.
        /// The IP:port is passed to this method as a string, and it is expected that the method will return true.
        /// </summary>
        public Func<string, bool> ClientDisconnected = null;

        /// <summary>
        /// Method to call when a message is received from a client.
        /// The IP:port is passed to this method as a string, along with a byte array containing the message data.
        /// It is expected that the method will return true.
        /// </summary>
        public Func<string, byte[], bool> MessageReceived = null;

        /// <summary>
        /// Method to call when a message is received from a client.
        /// The IP:port is passed to this method as a string, along with a long indicating the number of bytes to read from the stream.
        /// It is expected that the method will return true.
        /// </summary>
        public Func<string, long, Stream, bool> StreamReceived = null;

        /// <summary>
        /// Enable acceptance of SSL certificates from clients that cannot be validated.
        /// </summary>
        public bool AcceptInvalidCertificates = true;

        /// <summary>
        /// Require mutual authentication between SSL clients and this server.
        /// </summary>
        public bool MutuallyAuthenticate = false;

        /// <summary>
        /// Preshared key that must be consistent between clients and this server.
        /// </summary>
        public string PresharedKey = null;

        #endregion

        #region Private-Members

        private bool _Disposed = false;
        private int _ReadStreamBufferSize = 65536;
        private readonly Mode _Mode;
        private readonly string _ListenerIp;
        private readonly int _ListenerPort;
        private readonly IPAddress _ListenerIpAddress;
        private readonly TcpListener _Listener;

        private readonly X509Certificate2 _SslCertificate;

        private int _ActiveClients;
        private readonly ConcurrentDictionary<string, WatsonConnection> _Clients;
        private readonly ConcurrentDictionary<string, DateTime> _UnauthenticatedClients;

        private readonly CancellationTokenSource _TokenSource;
        private readonly CancellationToken _Token;

        #endregion

        #region Constructors-and-Factories

        /// <summary>
        /// Initialize the Watson TCP server without SSL.  Call Start() afterward to start Watson.
        /// </summary>
        /// <param name="listenerIp">The IP address on which the server should listen, nullable.</param>
        /// <param name="listenerPort">The TCP port on which the server should listen.</param>
        public WatsonTcpServer(
            string listenerIp,
            int listenerPort) :
            this(Mode.Tcp, listenerIp, listenerPort, null)
        {
        }

        /// <summary>
        /// Initialize the Watson TCP server with SSL.  Call Start() afterward to start Watson.
        /// </summary>
        /// <param name="listenerIp">The IP address on which the server should listen, nullable.</param>
        /// <param name="listenerPort">The TCP port on which the server should listen.</param>
        /// <param name="pfxCertFile">The file containing the SSL certificate.</param>
        /// <param name="pfxCertPass">The password for the SSL certificate.</param>
        public WatsonTcpServer(
            string listenerIp,
            int listenerPort,
            string pfxCertFile,
            string pfxCertPass) :
            this(Mode.Ssl, listenerIp, listenerPort, String.IsNullOrEmpty(pfxCertPass) ? new X509Certificate2(pfxCertFile) : new X509Certificate2(pfxCertFile, pfxCertPass))
        {
        }

        /// <summary>
        /// Initialize the Watson TCP server.  Call Start() afterward to start Watson.
        /// </summary>
        /// <param name="mode">If using TCP or SSL.</param>
        /// <param name="listenerIp">The IP address on which the server should listen, nullable.</param>
        /// <param name="listenerPort">The TCP port on which the server should listen.</param>
        /// <param name="certificate">The certificate to use, if using SSL.</param>
        public WatsonTcpServer(
            Mode mode,
            string listenerIp,
            int listenerPort,
            X509Certificate2 certificate)
        {
            if (listenerPort < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(listenerPort));
            }

            if (String.IsNullOrEmpty(listenerIp))
            {
                _ListenerIpAddress = IPAddress.Any;
                _ListenerIp = _ListenerIpAddress.ToString();
            }
            else
            {
                _ListenerIpAddress = IPAddress.Parse(listenerIp);
                _ListenerIp = listenerIp;
            }

            _Mode = mode;
            _ListenerPort = listenerPort;
            _Listener = new TcpListener(_ListenerIpAddress, _ListenerPort);

            if (_Mode == Mode.Ssl)
            {
                _SslCertificate = certificate;
            }

            _TokenSource = new CancellationTokenSource();
            _Token = _TokenSource.Token;

            _ActiveClients = 0;
            _Clients = new ConcurrentDictionary<string, WatsonConnection>();
            _UnauthenticatedClients = new ConcurrentDictionary<string, DateTime>();
        }

        #endregion

        #region Public-Methods

        /// <summary>
        /// Tear down the server and dispose of background workers.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Start the server.
        /// </summary>
        public void Start()
        {
            if (_Mode == Mode.Tcp)
            {
                Common.Log($"Watson TCP server starting on {_ListenerIp}:{_ListenerPort}");
            }
            else if (_Mode == Mode.Ssl)
            {
                Common.Log($"Watson TCP SSL server starting on {_ListenerIp}:{_ListenerPort}");
            }

            Task.Run(() => AcceptConnections(), _Token);
        }

        /// <summary>
        /// Send data to the specified client.
        /// </summary>
        /// <param name="ipPort">IP:port of the recipient client.</param>
        /// <param name="data">Byte array containing data.</param>
        /// <returns>Boolean indicating if the message was sent successfully.</returns>
        public bool Send(string ipPort, byte[] data)
        {
            if (!_Clients.TryGetValue(ipPort, out WatsonConnection client))
            {
                Common.Log($"*** Send unable to find client {ipPort}");
                return false;
            }

            return client.MessageWrite(MessageStatus.Normal, data, _ReadStreamBufferSize);
        }

        /// <summary>
        /// Send data to the specified client using a stream.
        /// </summary>
        /// <param name="ipPort">IP:port of the recipient client.</param>
        /// <param name="contentLength">The number of bytes in the stream.</param>
        /// <param name="stream">The stream containing the data.</param>
        /// <returns>Boolean indicating if the message was sent successfully.</returns>
        public bool Send(string ipPort, long contentLength, Stream stream)
        {
            if (!_Clients.TryGetValue(ipPort, out WatsonConnection client))
            {
                Common.Log($"*** Send unable to find client {ipPort}");
                return false;
            }

            WatsonMessage msg = new WatsonMessage(MessageStatus.Normal, contentLength, stream);
            return client.MessageWrite(msg, _ReadStreamBufferSize);
        }

        /// <summary>
        /// Send data to the specified client, asynchronously.
        /// </summary>
        /// <param name="ipPort">IP:port of the recipient client.</param>
        /// <param name="data">Byte array containing data.</param>
        /// <returns>Task with Boolean indicating if the message was sent successfully.</returns>
        public async Task<bool> SendAsync(string ipPort, byte[] data)
        {
            if (!_Clients.TryGetValue(ipPort, out WatsonConnection client))
            {
                Common.Log($"*** SendAsync unable to find client {ipPort}");
                return false;
            }

            return await client.MessageWriteAsync(MessageStatus.Normal, data, _ReadStreamBufferSize);
        }

        /// <summary>
        /// Send data to the specified client using a stream, asynchronously.
        /// </summary>
        /// <param name="ipPort">IP:port of the recipient client.</param>
        /// <param name="contentLength">The number of bytes in the stream.</param>
        /// <param name="stream">The stream containing the data.</param>
        /// <returns>Task with Boolean indicating if the message was sent successfully.</returns>
        public async Task<bool> SendAsync(string ipPort, long contentLength, Stream stream)
        {
            if (!_Clients.TryGetValue(ipPort, out WatsonConnection client))
            {
                Common.Log($"*** SendAsync unable to find client {ipPort}");
                return false;
            }

            WatsonMessage msg = new WatsonMessage(MessageStatus.Normal, contentLength, stream);
            return await client.MessageWriteAsync(msg, _ReadStreamBufferSize);
        }

        /// <summary>
        /// Determine whether or not the specified client is connected to the server.
        /// </summary>
        /// <returns>Boolean indicating if the client is connected to the server.</returns>
        public bool IsClientConnected(string ipPort)
        {
            return _Clients.TryGetValue(ipPort, out WatsonConnection client);
        }

        /// <summary>
        /// List the IP:port of each connected client.
        /// </summary>
        /// <returns>A string list containing each client IP:port.</returns>
        public List<string> ListClients()
        {
            Dictionary<string, WatsonConnection> clients = _Clients.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            List<string> ret = new List<string>();
            foreach (KeyValuePair<string, WatsonConnection> curr in clients)
            {
                ret.Add(curr.Key);
            }

            return ret;
        }

        /// <summary>
        /// Disconnects the specified client.
        /// </summary>
        public void DisconnectClient(string ipPort)
        {
            if (!_Clients.TryGetValue(ipPort, out WatsonConnection client))
            {
                Common.Log($"*** DisconnectClient unable to find client {ipPort}");
            }
            else
            {
                client.Dispose();
            }
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

                if (_Listener != null && _Listener.Server != null)
                {
                    _Listener.Server.Close();
                    _Listener.Server.Dispose();
                }

                if (_Clients != null && _Clients.Count > 0)
                {
                    foreach (KeyValuePair<string, WatsonConnection> currMetadata in _Clients)
                    {
                        currMetadata.Value.Dispose();
                    }
                }
            }

            _Disposed = true;
        }

        #endregion

        #region Private-Methods

        private async Task AcceptConnections()
        {
            _Listener.Start();
            while (!_Token.IsCancellationRequested)
            {
                string clientIpPort = String.Empty;

                try
                {
                    #region Accept-Connection-and-Validate-IP

                    TcpClient tcpClient = await _Listener.AcceptTcpClientAsync();
                    tcpClient.LingerState.Enabled = false;

                    string clientIp = ((IPEndPoint)tcpClient.Client.RemoteEndPoint).Address.ToString();
                    if (PermittedIPs != null && PermittedIPs.Count > 0)
                    {
                        if (!PermittedIPs.Contains(clientIp))
                        {
                            Common.Log($"*** AcceptConnections rejecting connection from {clientIp} (not permitted)");
                            tcpClient.Close();
                            continue;
                        }
                    }

                    WatsonConnection client = new WatsonConnection(tcpClient, _Mode, AcceptInvalidCertificates);
                    clientIpPort = client.IpPort;

                    #endregion

                    if (_Mode == Mode.Tcp)
                    {
                        #region Tcp

                        Task unawaited = Task.Run(() => FinalizeConnection(client), _Token);

                        #endregion
                    }
                    else if (_Mode == Mode.Ssl)
                    {
                        #region SSL

                        Task unawaited = Task.Run(() =>
                        {
                            Task<bool> success = StartTls(client);
                            if (success.Result)
                            {
                                FinalizeConnection(client);
                            }
                        }, _Token);

                        #endregion
                    }

                    Common.Log($"*** AcceptConnections accepted connection from {client.IpPort}");
                }
                catch (Exception e)
                {
                    Common.Log($"*** AcceptConnections exception {clientIpPort} {e.Message}");
                }
            }
        }

        private async Task<bool> StartTls(WatsonConnection client)
        {
            try
            {
                await client.SslStream.AuthenticateAsServerAsync(_SslCertificate, MutuallyAuthenticate, SslProtocols.Tls12, !AcceptInvalidCertificates);

                if (!client.SslStream.IsEncrypted)
                {
                    Common.Log($"*** StartTls stream from {client.IpPort} not encrypted");
                    client.Dispose();
                    return false;
                }

                if (!client.SslStream.IsAuthenticated)
                {
                    Common.Log($"*** StartTls stream from {client.IpPort} not authenticated");
                    client.Dispose();
                    return false;
                }

                if (MutuallyAuthenticate && !client.SslStream.IsMutuallyAuthenticated)
                {
                    Common.Log($"*** StartTls stream from {client.IpPort} failed mutual authentication");
                    client.Dispose();
                    return false;
                }
            }
            catch (IOException ex)
            {
                // Some type of problem initiating the SSL connection
                switch (ex.Message)
                {
                    case "Authentication failed because the remote party has closed the transport stream.":
                    case "Unable to read data from the transport connection: An existing connection was forcibly closed by the remote host.":
                        Common.Log($"*** StartTls IOException {client.IpPort} closed the connection.");
                        break;
                    case "The handshake failed due to an unexpected packet format.":
                        Common.Log($"*** StartTls IOException {client.IpPort} disconnected, invalid handshake.");
                        break;
                    default:
                        Common.Log($"*** StartTls IOException from {client.IpPort}{Environment.NewLine}{ex.ToString()}");
                        break;
                }

                client.Dispose();
                return false;
            }
            catch (Exception ex)
            {
                Common.Log($"*** StartTls Exception from {client.IpPort}{Environment.NewLine}{ex.ToString()}");
                client.Dispose();
                return false;
            }

            return true;
        }

        private void FinalizeConnection(WatsonConnection client)
        {
            #region Add-to-Client-List

            if (!AddClient(client))
            {
                Common.Log($"*** FinalizeConnection unable to add client {client.IpPort}");
                client.Dispose();
                return;
            }

            // Do not decrement in this block, decrement is done by the connection reader
            int activeCount = Interlocked.Increment(ref _ActiveClients);

            #endregion

            #region Request-Authentication

            if (!String.IsNullOrEmpty(PresharedKey))
            {
                Common.Log($"*** FinalizeConnection soliciting authentication material from {client.IpPort}");
                _UnauthenticatedClients.TryAdd(client.IpPort, DateTime.Now);

                byte[] data = Encoding.UTF8.GetBytes("Authentication required");
                client.MessageWrite(MessageStatus.AuthRequired, data, _ReadStreamBufferSize);
            }

            #endregion

            #region Start-Data-Receiver

            Common.Log($"*** FinalizeConnection starting data receiver for {client.IpPort} (now {activeCount} clients)");
            if (ClientConnected != null)
            {
                Task.Run(() => ClientConnected(client.IpPort));
            }

            Task.Run(async () => await DataReceiver(client));

            #endregion
        }

        private bool IsConnected(WatsonConnection client)
        {
            if (client.TcpClient.Connected)
            {
                byte[] tmp = new byte[1];
                bool success = false;
                bool sendLocked = false;
                bool readLocked = false;

                try
                {
                    client.WriteLock.Wait(1);
                    sendLocked = true;
                    client.TcpClient.Client.Send(tmp, 0, 0);
                    success = true;
                }
                catch (SocketException se)
                {
                    if (se.NativeErrorCode.Equals(10035))
                    {
                        success = true;
                    }
                }
                catch (Exception e)
                {
                    Common.Log($"*** IsConnected {client.IpPort} exception using send: {e.Message}");
                    success = false;
                }
                finally
                {
                    if (sendLocked)
                    {
                        client.WriteLock.Release();
                    }
                }

                if (success)
                {
                    return true;
                }

                try
                {
                    client.ReadLock.Wait(1);
                    readLocked = true;

                    if (client.TcpClient.Client.Poll(0, SelectMode.SelectWrite)
                        && (!client.TcpClient.Client.Poll(0, SelectMode.SelectError)))
                    {
                        byte[] buffer = new byte[1];
                        if (client.TcpClient.Client.Receive(buffer, SocketFlags.Peek) == 0)
                        {
                            return false;
                        }
                        else
                        {
                            return true;
                        }
                    }
                    else
                    {
                        return false;
                    }
                }
                catch (Exception e)
                {
                    Common.Log($"*** IsConnected {client.IpPort} exception using poll/peek: {e.Message}");
                    return false;
                }
                finally
                {
                    if (readLocked)
                    {
                        client.ReadLock.Release();
                    }
                }
            }
            else
            {
                return false;
            }
        }

        private async Task DataReceiver(WatsonConnection client)
        {
            try
            {
                #region Wait-for-Data

                while (true)
                {
                    try
                    {
                        if (!IsConnected(client))
                        {
                            break;
                        }

                        WatsonMessage msg = null;

                        client.ReadLock.Wait(1);

                        try
                        {
                            msg = await client.MessageReadAsync(ReadDataStream);
                        }
                        finally
                        {
                            client.ReadLock.Release();
                        }

                        if (msg == null)
                        {
                            // no message available
                            await Task.Delay(30);
                            continue;
                        }

                        if (!String.IsNullOrEmpty(PresharedKey))
                        {
                            if (_UnauthenticatedClients.ContainsKey(client.IpPort))
                            {
                                Common.Log($"*** DataReceiver message received from unauthenticated endpoint: {client.IpPort}");

                                if (msg.Status == MessageStatus.AuthRequested)
                                {
                                    // check preshared key
                                    if (msg.PresharedKey != null && msg.PresharedKey.Length > 0)
                                    {
                                        string clientPsk = Encoding.UTF8.GetString(msg.PresharedKey).Trim();
                                        if (PresharedKey.Trim().Equals(clientPsk))
                                        {
                                            Common.Log($"DataReceiver accepted authentication from {client.IpPort}");

                                            _UnauthenticatedClients.TryRemove(client.IpPort, out DateTime dt);
                                            byte[] data = Encoding.UTF8.GetBytes("Authentication successful");
                                            client.MessageWrite(MessageStatus.AuthSuccess, data, _ReadStreamBufferSize);
                                            continue;
                                        }
                                        else
                                        {
                                            Common.Log($"DataReceiver declined authentication from {client.IpPort}");

                                            byte[] data = Encoding.UTF8.GetBytes("Authentication declined");
                                            client.MessageWrite(MessageStatus.AuthFailure, data, _ReadStreamBufferSize);
                                            continue;
                                        }
                                    }
                                    else
                                    {
                                        Common.Log($"DataReceiver no authentication material from {client.IpPort}");

                                        byte[] data = Encoding.UTF8.GetBytes("No authentication material");
                                        client.MessageWrite(MessageStatus.AuthFailure, data, _ReadStreamBufferSize);
                                        continue;
                                    }
                                }
                                else
                                {
                                    // decline the message
                                    Common.Log($"DataReceiver no authentication material from {client.IpPort}");

                                    byte[] data = Encoding.UTF8.GetBytes("Authentication required");
                                    client.MessageWrite(MessageStatus.AuthRequired, data, _ReadStreamBufferSize);
                                    continue;
                                }
                            }
                        }

                        if (ReadDataStream)
                        {
                            if (MessageReceived != null)
                            {
                                Task<bool> unawaited = Task.Run(() => MessageReceived(client.IpPort, msg.Data));
                            }
                        }
                        else
                        {
                            StreamReceived?.Invoke(client.IpPort, msg.ContentLength, msg.DataStream);
                        }
                    }
                    catch (Exception)
                    {
                        break;
                    }
                }

                #endregion
            }
            finally
            {
                int activeCount = Interlocked.Decrement(ref _ActiveClients);
                RemoveClient(client);

                if (ClientDisconnected != null)
                {
                    Task<bool> unawaited = Task.Run(() => ClientDisconnected(client.IpPort));
                }

                Common.Log($"*** DataReceiver client {client.IpPort} disconnected (now {activeCount} clients active)");
                client.Dispose();
            }
        }

        private bool AddClient(WatsonConnection client)
        {
            _Clients.TryRemove(client.IpPort, out WatsonConnection removedClient);
            _Clients.TryAdd(client.IpPort, client);

            Common.Log($"*** AddClient added client {client.IpPort}");
            return true;
        }

        private bool RemoveClient(WatsonConnection client)
        {
            _Clients.TryRemove(client.IpPort, out WatsonConnection removedClient);
            _UnauthenticatedClients.TryRemove(client.IpPort, out DateTime dt);

            Common.Log($"*** RemoveClient removed client {client.IpPort}");
            return true;
        }

        #endregion
    }
}
