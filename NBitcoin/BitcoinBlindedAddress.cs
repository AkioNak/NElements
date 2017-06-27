using NBitcoin.DataEncoders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NBitcoin
{
	public class BitcoinBlindedAddress : BitcoinAddress, IBase58Data
	{
		public BitcoinBlindedAddress(string base58, Network expectedNetwork = null)
			: base(Validate(base58, ref expectedNetwork), expectedNetwork)
		{
			var data = Encoders.Base58Check.DecodeData(base58);

			PubKey p = null;
			TxDestination h = null;
			Validate(base58, ref expectedNetwork, ref p, ref h);
			_Hash = h;
			_BlindingKey = p;
		}

		private static string Validate(string base58, ref Network expectedNetwork)
		{
			PubKey p = null;
			TxDestination h = null;
			return Validate(base58, ref expectedNetwork, ref p, ref h);
		}

		private static string Validate(string base58, ref Network expectedNetwork, ref PubKey blinding, ref TxDestination hash)
		{
			if(base58 == null)
				throw new ArgumentNullException("base58");
			var networks = expectedNetwork == null ? Network.GetNetworks() : new[] { expectedNetwork };
			var data = Encoders.Base58Check.DecodeData(base58);
			foreach(var network in networks)
			{
				bool isP2SH = false;
				var versionBytes = network.GetVersionBytes(Base58Type.BLINDED_ADDRESS, false);
				if(versionBytes == null || !data.StartWith(versionBytes))
					continue;
				var innerData = data.Skip(versionBytes.Length).ToArray();
				var versionBytes2 = network.GetVersionBytes(Base58Type.PUBKEY_ADDRESS, false);
				if(!innerData.StartWith(versionBytes2))
				{
					versionBytes2 = network.GetVersionBytes(Base58Type.SCRIPT_ADDRESS, false);
					if(!innerData.StartWith(versionBytes2))
					{
						continue;
					}
					isP2SH = true;
				}

				if(innerData.Length != versionBytes2.Length + 33 + 20)
					continue;
				try
				{
					blinding = new PubKey(innerData.SafeSubarray(versionBytes2.Length, 33));
					var h = innerData.SafeSubarray(versionBytes2.Length + 33, 20);
					hash = isP2SH ? (TxDestination)new ScriptId(h) : new KeyId(h);
				}
				catch(FormatException) { continue; }
				expectedNetwork = network;
				return base58;
			}
			throw new FormatException("Invalid BitcoinBlindedAddress");
		}


		public BitcoinBlindedAddress(PubKey blindingKey, TxDestination keyId, Network network)
				: base(NotNull(keyId, nameof(keyId)) ?? 
					   NotNull(blindingKey, nameof(blindingKey)) ?? 
					   Network.CreateBase58(Base58Type.BLINDED_ADDRESS, 
										network.GetVersionBytes(((IBase58Data)keyId.GetAddress(network)).Type, true)
										.Concat(blindingKey.ToBytes())
										.Concat(keyId.ToBytes()), network), network)
		{
			_BlindingKey = blindingKey;
			_Hash = keyId;
		}

		private static string NotNull<T>(T o, string name) where T : class
		{
			if(o == null)
				throw new ArgumentNullException(name);
			return null;
		}

		public Base58Type Type
		{
			get
			{
				return Base58Type.BLINDED_ADDRESS;
			}
		}

		private bool StartWith(byte[] a, byte[] b)
		{
			if(a.Length < b.Length)
				return false;
			for(int i = 0; i < b.Length; i++)
			{
				if(a[i] != b[i])
					return false;
			}
			return true;
		}

		TxDestination _Hash;
		public TxDestination Hash
		{
			get
			{
				return _Hash;
			}
		}

		public BitcoinAddress UnblindedAddress
		{
			get
			{
				return _Hash.GetAddress(Network);
			}
		}

		PubKey _BlindingKey;
		public PubKey BlindingKey
		{
			get
			{
				return _BlindingKey;
			}
		}

		protected override Script GeneratePaymentScript()
		{
			return _Hash.ScriptPubKey;
		}

		protected override BitcoinBlindedAddress CreateBlindedAddressCore(PubKey blinded)
		{
			return this;
		}
	}
}
