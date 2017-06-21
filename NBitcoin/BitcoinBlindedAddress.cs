using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NBitcoin
{
	public class BitcoinBlindedAddress : BitcoinAddress
	{
		public BitcoinBlindedAddress(string base58, Network expectedNetwork = null)
			: base(base58, expectedNetwork)
		{
		}

		public BitcoinBlindedAddress(PubKey pubKey, TxDestination keyId, Network network)
			: base(GetRawBytes(pubKey, keyId, network), network)
		{
		}

		private static byte[] GetRawBytes(PubKey pubKey, TxDestination keyId, Network network)
		{
			if(network == null)
				throw new ArgumentNullException("network");
			return network.GetVersionBytes(keyId.GetAddress(network).Type).Concat(pubKey.ToBytes(), keyId.ToBytes());
		}

		public override Base58Type Type
		{
			get
			{
				return Base58Type.BLINDED_ADDRESS;
			}
		}

		protected override bool IsValid
		{
			get
			{
				if(_BlindingKey != null)
					return true;

				var version = Network.GetVersionBytes(Base58Type.PUBKEY_ADDRESS);
				if(!StartWith(vchData, version))
				{
					version = Network.GetVersionBytes(Base58Type.SCRIPT_ADDRESS);
					if(!StartWith(vchData, version))
					{
						return false;
					}
				}

				if(vchData.Length != version.Length + 33 + 20)
					return false;
				var blinding = vchData.SafeSubarray(version.Length, 33);
				if(PubKey.Check(blinding, true))
				{
					_BlindingKey = new PubKey(blinding);
					_Hash = new KeyId(vchData.SafeSubarray(version.Length + 33, 20));
				}
				return _BlindingKey != null;
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
