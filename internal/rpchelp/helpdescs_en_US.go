// Copyright (c) 2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build !generate
// +build !generate

package rpchelp

var helpDescsEnUS = map[string]string{
	// AddMultisigAddressCmd help.
	"addmultisigaddress--synopsis": "Generates and imports a multisig address and redeeming script to the 'imported' account.",
	"addmultisigaddress-account":   "DEPRECATED -- Unused (all imported addresses belong to the imported account).",
	"addmultisigaddress-keys":      "Pubkeys and/or pay-to-pubkey-hash addresses to partially control the multisig address.",
	"addmultisigaddress-nrequired": "The number of signatures required to redeem outputs paid to this address.",
	"addmultisigaddress--result0":  "The imported pay-to-script-hash address.",

	// CreateMultisigCmd help.
	"createmultisig--synopsis": "Generate a multisig address and redeem script.",
	"createmultisig-keys":      "Pubkeys and/or pay-to-pubkey-hash addresses to partially control the multisig address.",
	"createmultisig-nrequired": "The number of signatures required to redeem outputs paid to this address.",

	// CreateMultisigResult help.
	"createmultisigresult-address":      "The generated pay-to-script-hash address.",
	"createmultisigresult-redeemScript": "The script required to redeem outputs paid to the multisig address.",

	// CreateNewAccountCmd help.
	"createnewaccount--synopsis": "Creates a new account.",
	"createnewaccount-account":   "Account name.",

	// DumpPrivKeyCmd help.
	"dumpprivkey--synopsis": "Returns the private key in WIF encoding that controls some wallet address.",
	"dumpprivkey-address":   "The address to return a private key for.",
	"dumpprivkey--result0":  "The WIF-encoded private key.",

	// ExportWatchingWalletCmd help.
	"exportwatchingwallet--synopsis": "Creates and returns a duplicate of the wallet database without any private keys to be used as a watching-only wallet.",
	"exportwatchingwallet-account":   "Unused (must be unset or \"*\").",
	"exportwatchingwallet-download":  "Unused.",
	"exportwatchingwallet--result0":  "The watching-only database encoded as a base64 string.",

	// GetAccountCmd help.
	"getaccount--synopsis": "Lookup the account name that some wallet address belongs to.",
	"getaccount-address":   "The address to query the account for.",
	"getaccount--result0":  "The name of the account that 'address' belongs to.",

	// GetAccountAddressCmd help.
	"getaccountaddress--synopsis": "Returns the most recent external payment address for an account that has not been seen publicly.\n" +
		"A new address is generated for the account if the most recently generated address has been seen on the blockchain or in mempool.",
	"getaccountaddress-account":     "The account of the returned address. Defaults to 'default'",
	"getaccountaddress-addresstype": "Address type. Must be one of 'legacy', 'p2sh-segwit', or 'bech32'. Default to 'legacy'.",
	"getaccountaddress--result0":    "The unused address for 'account'.",

	// GetAddressesByAccountCmd help.
	"getaddressesbyaccount--synopsis":   "Returns all addresses controlled by a single account.",
	"getaddressesbyaccount-account":     "Account name to fetch addresses for. Defaults to 'default'",
	"getaddressesbyaccount-addresstype": "Address type filter. Must be one of 'legacy', 'p2sh-segwit', 'bech32', or '*'. Defaults to '*'.",
	"getaddressesbyaccount--result0":    "All addresses controlled by 'account' filtered by 'addresstype'.",

	// GetBalanceCmd help.
	"getbalance--synopsis":   "Calculates and returns the balance of one or all accounts.",
	"getbalance-minconf":     "Minimum number of block confirmations required before an unspent output's value is included in the balance.",
	"getbalance-account":     "Account name or '*' for all accounts to query the balance for. Default to 'default'.",
	"getbalance-addresstype": "Address type filter. Must be one of 'legacy', 'p2sh-segwit', 'bech32', or '*'. Default to '*'.",
	"getbalance--result0":    "The balance valued in LBC.",

	// GetBestBlockCmd help.
	"getbestblock--synopsis": "Returns the hash and height of the newest block in the best chain that wallet has finished syncing with.",

	// GetBestBlockResult help.
	"getbestblockresult-hash":   "The hash of the block.",
	"getbestblockresult-height": "The blockchain height of the block.",

	// GetBestBlockHashCmd help.
	"getbestblockhash--synopsis": "Returns the hash of the newest block in the best chain that wallet has finished syncing with.",
	"getbestblockhash--result0":  "The hash of the most recent synced-to block.",

	// GetBlockCountCmd help.
	"getblockcount--synopsis": "Returns the blockchain height of the newest block in the best chain that wallet has finished syncing with.",
	"getblockcount--result0":  "The blockchain height of the most recent synced-to block.",

	// GetInfoCmd help.
	"getinfo--synopsis": "Returns a JSON object containing various state info.",

	// GetUnconfirmedBalanceCmd help.
	"getunconfirmedbalance--synopsis": "Calculates the unspent output value of all unmined transaction outputs.",
	"getunconfirmedbalance-account":   "The account name to query the unconfirmed balance for. Default to 'default'.",
	"getunconfirmedbalance--result0":  "Total amount of all unmined unspent outputs of the account valued in LBC.",

	// GetAddressInfoCmd help.
	"getaddressinfo--synopsis": "Generates and returns a new payment address.",
	"getaddressinfo-address":   "The address to get the information of.",

	// GetAddressInfoResult help.
	"getaddressinforesult-embedded":            "Information about the address embedded in P2SH or P2WSH, if relevant and known.",
	"getaddressinforesult-ismine":              "If the address is yours.",
	"getaddressinforesult-iswatchonly":         "If the address is watchonly.",
	"getaddressinforesult-timestamp":           "The creation time of the key, if available, expressed in UNIX epoch time.",
	"getaddressinforesult-hdkeypath":           "The HD keypath, if the key is HD and available.",
	"getaddressinforesult-hdseedid":            "The Hash160 of the HD seed.",
	"getaddressinforesult-address":             "The address validatedi.",
	"getaddressinforesult-scriptPubKey":        "The hex-encoded scriptPubKey generated by the address.",
	"getaddressinforesult-desc":                "A descriptor for spending coins sent to this address (only when solvable).",
	"getaddressinforesult-isscript":            "If the key is a script.",
	"getaddressinforesult-ischange":            "If the address was used for change output.",
	"getaddressinforesult-iswitness":           "If the address is a witness address.",
	"getaddressinforesult-witness_version":     "The version number of the witness program.",
	"getaddressinforesult-witness_program":     "The hex value of the witness program.",
	"getaddressinforesult-script":              "The output script type. Only if isscript is true and the redeemscript is known.  Possible types: nonstandard, pubkey, pubkeyhash, scripthash, multisig, nulldata, witness_v0_keyhash, witness_v0_scripthash, witness_unknown.",
	"getaddressinforesult-hex":                 "The redeemscript for the p2sh address.",
	"getaddressinforesult-pubkeys":             "The hex value of the raw public key for single-key addresses (possibly embedded in P2SH or P2WSH).",
	"getaddressinforesult-sigsrequired":        "The number of signatures required to spend multisig output (only if script is multisig).",
	"getaddressinforesult-pubkey":              "Array of pubkeys associated with the known redeemscript (only if script is multisig).",
	"getaddressinforesult-iscompressed":        "If the pubkey is compressed.",
	"getaddressinforesult-hdmasterfingerprint": "The fingerprint of the master key.",
	"getaddressinforesult-labels":              "Array of labels associated with the address. Currently limited to one label but returned.",
	"embeddedaddressinfo-address":              "The address validated.",
	"embeddedaddressinfo-scriptPubKey":         "The hex-encoded scriptPubKey generated by the address.",
	"embeddedaddressinfo-desc":                 "A descriptor for spending coins sent to this address (only when solvable).",
	"embeddedaddressinfo-isscript":             "If the key is a script.",
	"embeddedaddressinfo-ischange":             "If the address was used for change output.",
	"embeddedaddressinfo-iswitness":            "If the address is a witness address.",
	"embeddedaddressinfo-witness_version":      "The version number of the witness program.",
	"embeddedaddressinfo-witness_program":      "The hex value of the witness program.",
	"embeddedaddressinfo-script":               "The output script type. Only if isscript is true and the redeemscript is known.  Possible types: nonstandard, pubkey, pubkeyhash, scripthash, multisig, nulldata, witness_v0_keyhash, witness_v0_scripthash, witness_unknown.",
	"embeddedaddressinfo-hex":                  "The redeemscript for the p2sh address.",
	"embeddedaddressinfo-pubkeys":              "The hex value of the raw public key for single-key addresses (possibly embedded in P2SH or P2WSH).",
	"embeddedaddressinfo-sigsrequired":         "The number of signatures required to spend multisig output (only if script is multisig).",
	"embeddedaddressinfo-pubkey":               "Array of pubkeys associated with the known redeemscript (only if script is multisig).",
	"embeddedaddressinfo-iscompressed":         "If the pubkey is compressed.",
	"embeddedaddressinfo-hdmasterfingerprint":  "The fingerprint of the master key.",
	"embeddedaddressinfo-labels":               "Array of labels associated with the address. Currently limited to one label but returned.",

	// GetNewAddressCmd help.
	"getnewaddress--synopsis":   "Generates and returns a new payment address.",
	"getnewaddress-account":     "Account name the new address will belong to. Defaults to 'default'.",
	"getnewaddress-addresstype": "Address type. Must be one of 'legacy', 'p2sh-segwit', or 'bech32'. Default to 'legacy'.",
	"getnewaddress--result0":    "The payment address.",

	// GetRawChangeAddressCmd help.
	"getrawchangeaddress--synopsis":   "Generates and returns a new internal payment address for use as a change address in raw transactions.",
	"getrawchangeaddress-account":     "Account name the new internal address will belong to. Defaults to 'default'.",
	"getrawchangeaddress-addresstype": "Address type. Must be one of 'legacy', 'p2sh-segwit', or 'bech32'. Default to 'legacy'.",
	"getrawchangeaddress--result0":    "The internal payment address.",

	// GetReceivedByAccountCmd help.
	"getreceivedbyaccount--synopsis": "Returns the total amount received by addresses of some account, including spent outputs.",
	"getreceivedbyaccount-account":   "Account name to query total received amount for. Defaults to 'default'",
	"getreceivedbyaccount-minconf":   "Minimum number of block confirmations required before an output's value is included in the total. Defaults to 0",
	"getreceivedbyaccount--result0":  "The total received amount valued in LBC.",

	// GetReceivedByAddressCmd help.
	"getreceivedbyaddress--synopsis": "Returns the total amount received by a single address, including spent outputs.",
	"getreceivedbyaddress-address":   "Payment address which received outputs to include in total.",
	"getreceivedbyaddress-minconf":   "Minimum number of block confirmations required before an output's value is included in the total. Defaults to 1",
	"getreceivedbyaddress--result0":  "The total received amount valued in LBC.",

	// GetTransactionCmd help.
	"gettransaction--synopsis":        "Returns a JSON object with details regarding a transaction relevant to this wallet.",
	"gettransaction-txid":             "Hash of the transaction to query.",
	"gettransaction-includewatchonly": "Also consider transactions involving watched addresses.",

	// GetTransactionResult help.
	"gettransactionresult-amount":          "The total amount this transaction credits to the wallet, valued in LBC.",
	"gettransactionresult-fee":             "The total input value minus the total output value, or 0 if 'txid' is not a sent transaction.",
	"gettransactionresult-confirmations":   "The number of block confirmations of the transaction.",
	"gettransactionresult-generated":       "Only present if transaction only input is a coinbase one.",
	"gettransactionresult-blockhash":       "The hash of the block this transaction is mined in, or the empty string if unmined.",
	"gettransactionresult-blockindex":      "Unset.",
	"gettransactionresult-blocktime":       "The Unix time of the block header this transaction is mined in, or 0 if unmined.",
	"gettransactionresult-txid":            "The transaction hash.",
	"gettransactionresult-walletconflicts": "Unset.",
	"gettransactionresult-time":            "The earliest Unix time this transaction was known to exist.",
	"gettransactionresult-timereceived":    "The earliest Unix time this transaction was known to exist.",
	"gettransactionresult-details":         "Additional details for each recorded wallet credit and debit.",
	"gettransactionresult-hex":             "The transaction encoded as a hexadecimal string.",

	// GetTransactionDetailsResult help.
	"gettransactiondetailsresult-account":           "The account pertaining to this transaction.",
	"gettransactiondetailsresult-address":           "The address an output was paid to, or the empty string if the output is nonstandard or this detail is regarding a transaction input.",
	"gettransactiondetailsresult-category":          `The kind of detail: "send" for sent transactions, "immature" for immature coinbase outputs, "generate" for mature coinbase outputs, or "recv" for all other received outputs.`,
	"gettransactiondetailsresult-amount":            "The amount of a received output.",
	"gettransactiondetailsresult-fee":               "The included fee for a sent transaction.",
	"gettransactiondetailsresult-vout":              "The transaction output index.",
	"gettransactiondetailsresult-involveswatchonly": "Unset.",

	// HelpCmd help.
	"help--synopsis":   "Returns a list of all commands or help for a specified command.",
	"help-command":     "The command to retrieve help for.",
	"help--condition0": "no command provided.",
	"help--condition1": "command specified.",
	"help--result0":    "List of commands.",
	"help--result1":    "Help for specified command.",

	// ImportPrivKeyCmd help.
	"importprivkey--synopsis": "Imports a WIF-encoded private key to the 'imported' account.",
	"importprivkey-privkey":   "The WIF-encoded private key.",
	"importprivkey-label":     "Unused (must be unset or 'imported').",
	"importprivkey-rescan":    "Rescan the blockchain (since the genesis block) for outputs controlled by the imported key.",

	// InfoWalletResult help.
	"infowalletresult-version":         "The version of the server.",
	"infowalletresult-protocolversion": "The latest supported protocol version.",
	"infowalletresult-blocks":          "The number of blocks processed.",
	"infowalletresult-timeoffset":      "The time offset.",
	"infowalletresult-connections":     "The number of connected peers.",
	"infowalletresult-proxy":           "The proxy used by the server.",
	"infowalletresult-difficulty":      "The current target difficulty.",
	"infowalletresult-testnet":         "Whether or not server is using testnet.",
	"infowalletresult-relayfee":        "The minimum relay fee for non-free transactions in LBC/KB.",
	"infowalletresult-errors":          "Any current errors.",
	"infowalletresult-paytxfee":        "The increment used each time more fee is required for an authored transaction.",
	"infowalletresult-balance":         "The non-staked balance of all accounts calculated with one block confirmation.",
	"infowalletresult-staked":          "The staked balance of all accounts calculated with one block confirmation.",
	"infowalletresult-walletversion":   "The version of the address manager database.",
	"infowalletresult-unlocked_until":  "Unset.",
	"infowalletresult-keypoolsize":     "Unset.",
	"infowalletresult-keypoololdest":   "Unset.",

	// KeypoolRefillCmd help.
	"keypoolrefill--synopsis": "DEPRECATED -- This request does nothing since no keypool is maintained.",
	"keypoolrefill-newsize":   "Unused.",

	// ListAccountsCmd help.
	"listaccounts--synopsis":       "Returns a JSON object of all accounts and their balances.",
	"listaccounts-minconf":         "Minimum number of block confirmations required before an unspent output's value is included in the balance.",
	"listaccounts-addresstype":     "Address type filter. Must be one of 'legacy', 'p2sh-segwit', 'bech32', or '*'. Defaults to '*'.",
	"listaccounts--result0--desc":  "JSON object with account names as keys and LBC amounts as values.",
	"listaccounts--result0--key":   "Account name",
	"listaccounts--result0--value": "Total balance and each scope respectively, valued in LBC.",

	// ListAddressTransactionsCmd help.
	"listaddresstransactions--synopsis": "Returns a JSON array of objects containing verbose details for wallet transactions pertaining some addresses.",
	"listaddresstransactions-addresses": "Addresses to filter transaction results by.",
	"listaddresstransactions-account":   "Account to filter transactions results by. Defaults to 'default'.",

	// ListAllTransactionsCmd help.
	"listalltransactions--synopsis": "Returns a JSON array of objects in the same format as 'listtransactions' without limiting the number of returned objects.",
	"listalltransactions-account":   "Account to filter transactions results by. Defaults to 'default'.",

	// ListLockUnspentCmd help.
	"listlockunspent--synopsis": "Returns a JSON array of outpoints marked as locked (with lockunspent) for this wallet session.",

	// TransactionInput help.
	"transactioninput-txid": "The transaction hash of the referenced output.",
	"transactioninput-vout": "The output index of the referenced output.",

	// ListReceivedByAccountCmd help.
	"listreceivedbyaccount--synopsis":        "Returns a JSON array of objects listing all accounts and the total amount received by each account.",
	"listreceivedbyaccount-minconf":          "Minimum number of block confirmations required before a transaction is considered.",
	"listreceivedbyaccount-includeempty":     "Unused.",
	"listreceivedbyaccount-includewatchonly": "Unused.",

	// ListReceivedByAccountResult help.
	"listreceivedbyaccountresult-account":       "Account name.",
	"listreceivedbyaccountresult-amount":        "Total amount received by payment addresses of the account valued in LBC.",
	"listreceivedbyaccountresult-confirmations": "Number of block confirmations of the most recent transaction relevant to the account.",

	// ListReceivedByAddressCmd help.
	"listreceivedbyaddress--synopsis":        "Returns a JSON array of objects listing wallet payment addresses and their total received amounts.",
	"listreceivedbyaddress-minconf":          "Minimum number of block confirmations required before a transaction is considered.",
	"listreceivedbyaddress-includeempty":     "Unused.",
	"listreceivedbyaddress-includewatchonly": "Unused.",

	// ListReceivedByAddressResult help.
	"listreceivedbyaddressresult-address":           "The payment address.",
	"listreceivedbyaddressresult-amount":            "Total amount received by the payment address valued in LBC.",
	"listreceivedbyaddressresult-confirmations":     "Number of block confirmations of the most recent transaction relevant to the address.",
	"listreceivedbyaddressresult-txids":             "Transaction hashes of all transactions involving this address.",
	"listreceivedbyaddressresult-involvesWatchonly": "Unset.",

	// ListSinceBlockCmd help.
	"listsinceblock--synopsis":           "Returns a JSON array of objects listing details of all wallet transactions after some block.",
	"listsinceblock-blockhash":           "Hash of the parent block of the first block to consider transactions from, or unset to list all transactions.",
	"listsinceblock-targetconfirmations": "Minimum number of block confirmations of the last block in the result object.  Must be 1 or greater.  Note: The transactions array in the result object is not affected by this parameter.",
	"listsinceblock-includewatchonly":    "Unused.",
	"listsinceblock--condition0":         "blockhash specified.",
	"listsinceblock--condition1":         "no blockhash specified.",
	"listsinceblock--result0":            "Lists all transactions, including unmined transactions, since the specified block.",
	"listsinceblock--result1":            "Lists all transactions since the genesis block.",

	// ListSinceBlockResult help.
	"listsinceblockresult-transactions": "JSON array of objects containing verbose details of the each transaction.",
	"listsinceblockresult-lastblock":    "Hash of the latest-synced block to be used in later calls to listsinceblock.",

	// ListTransactionsCmd help.
	"listtransactions--synopsis":        "Returns a JSON array of objects containing verbose details for wallet transactions.",
	"listtransactions-account":          "Account to filter transactions results by. Defaults to 'default'.",
	"listtransactions-count":            "Maximum number of transactions to create results from. Defaults to 10",
	"listtransactions-from":             "Number of transactions to skip before results are created.",
	"listtransactions-includewatchonly": "Unused.",

	// ListTransactionsResult help.
	"listtransactionsresult-account":            "The account name associated with the transaction.",
	"listtransactionsresult-address":            "Payment address for a transaction output.",
	"listtransactionsresult-category":           `The kind of transaction: "send" for sent transactions, "immature" for immature coinbase outputs, "generate" for mature coinbase outputs, or "recv" for all other received outputs.  Note: A single output may be included multiple times under different categories`,
	"listtransactionsresult-amount":             "The value of the transaction output valued in LBC.",
	"listtransactionsresult-fee":                "The total input value minus the total output value for sent transactions.",
	"listtransactionsresult-confirmations":      "The number of block confirmations of the transaction.",
	"listtransactionsresult-generated":          "Whether the transaction output is a coinbase output.",
	"listtransactionsresult-blockhash":          "The hash of the block this transaction is mined in, or the empty string if unmined.",
	"listtransactionsresult-blockheight":        "The block height containing the transaction.",
	"listtransactionsresult-blockindex":         "Unset.",
	"listtransactionsresult-blocktime":          "The Unix time of the block header this transaction is mined in, or 0 if unmined.",
	"listtransactionsresult-label":              "A comment for the address/transaction, if any.",
	"listtransactionsresult-txid":               "The hash of the transaction.",
	"listtransactionsresult-vout":               "The transaction output index.",
	"listtransactionsresult-walletconflicts":    "Unset.",
	"listtransactionsresult-time":               "The earliest Unix time this transaction was known to exist.",
	"listtransactionsresult-timereceived":       "The earliest Unix time this transaction was known to exist.",
	"listtransactionsresult-involveswatchonly":  "Unset.",
	"listtransactionsresult-comment":            "Unset.",
	"listtransactionsresult-otheraccount":       "Unset.",
	"listtransactionsresult-trusted":            "Unset.",
	"listtransactionsresult-bip125-replaceable": "Unset.",
	"listtransactionsresult-abandoned":          "Unset.",

	// ListUnspentCmd help.
	"listunspent--synopsis": "Returns a JSON array of objects representing unlocked unspent outputs controlled by wallet keys.",
	"listunspent-minconf":   "Minimum number of block confirmations required before a transaction output is considered.",
	"listunspent-maxconf":   "Maximum number of block confirmations required before a transaction output is excluded.",
	"listunspent-addresses": "If set, limits the returned details to unspent outputs received by any of these payment addresses.",

	// ListUnspentResult help.
	"listunspentresult-txid":          "The transaction hash of the referenced output.",
	"listunspentresult-vout":          "The output index of the referenced output.",
	"listunspentresult-address":       "The payment address that received the output.",
	"listunspentresult-account":       "The account associated with the receiving payment address.",
	"listunspentresult-scriptPubKey":  "The output script encoded as a hexadecimal string.",
	"listunspentresult-redeemScript":  "Unset.",
	"listunspentresult-amount":        "The amount of the output valued in LBC.",
	"listunspentresult-confirmations": "The number of block confirmations of the transaction.",
	"listunspentresult-solvable":      "Whether the output is solvable.",
	"listunspentresult-spendable":     "Whether the output is entirely controlled by wallet keys/scripts (false for partially controlled multisig outputs or outputs to watch-only addresses).",
	"listunspentresult-isstake":       "Whether the output is staked.",

	// LockUnspentCmd help.
	"lockunspent--synopsis": "Locks or unlocks an unspent output.\n" +
		"Locked outputs are not chosen for transaction inputs of authored transactions and are not included in 'listunspent' results.\n" +
		"Locked outputs are volatile and are not saved across wallet restarts.\n" +
		"If unlock is true and no transaction outputs are specified, all locked outputs are marked unlocked.",
	"lockunspent-unlock":       "True to unlock outputs, false to lock.",
	"lockunspent-transactions": "Transaction outputs to lock or unlock.",
	"lockunspent--result0":     "The boolean 'true'.",

	// RenameAccountCmd help.
	"renameaccount--synopsis":  "Renames an account.",
	"renameaccount-oldaccount": "The old account name to rename.",
	"renameaccount-newaccount": "The new name for the account.",

	// RescanBlockchainCmd help.
	"rescanblockchain--synopsis":   "Renames an account.",
	"rescanblockchain-startheight": "Block height where the rescan should start.",
	"rescanblockchain-stopheight":  "The last block height that should be scanned. If none is provided it will rescan up to the tip at return time of this call.",

	// RescanblockchainResult help.
	"rescanblockchainresult-start_height": "The block height where the rescan started (the requested height or 0)",
	"rescanblockchainresult-stop_height":  "The height of the last rescanned block.",

	// SendFromCmd help.
	"sendfrom--synopsis": "Authors, signs, and sends a transaction that outputs some amount to a payment address.\n" +
		"A change output is automatically included to send extra output value back to the original account.",
	"sendfrom-fromaccount": "Account to pick unspent outputs from.",
	"sendfrom-toaddress":   "Address to pay.",
	"sendfrom-amount":      "Amount to send to the payment address valued in LBC.",
	"sendfrom-minconf":     "Minimum number of block confirmations required before a transaction output is eligible to be spent.",
	"sendfrom-addresstype": "Address type filter for UTXOs to spent from. Must be one of 'legacy', 'p2sh-segwit', 'bech32', or '*'. Defaults to '*'.",
	"sendfrom-comment":     "Unused.",
	"sendfrom-commentto":   "Unused.",
	"sendfrom--result0":    "The transaction hash of the sent transaction.",

	// SendManyCmd help.
	"sendmany--synopsis": "Authors, signs, and sends a transaction that outputs to many payment addresses.\n" +
		"A change output is automatically included to send extra output value back to the original account.",
	"sendmany-fromaccount":    "Account to pick unspent outputs from.",
	"sendmany-amounts":        "Pairs of payment addresses and the output amount to pay each.",
	"sendmany-amounts--desc":  "JSON object using payment addresses as keys and output amounts valued in LBC to send to each address.",
	"sendmany-amounts--key":   "Address to pay.",
	"sendmany-amounts--value": "Amount to send to the payment address valued in LBC.",
	"sendmany-minconf":        "Minimum number of block confirmations required before a transaction output is eligible to be spent.",
	"sendmany-addresstype":    "Address type filter for UTXOs to spent from. Must be one of 'legacy', 'p2sh-segwit', 'bech32', or '*'. Defaults to '*'.",
	"sendmany-comment":        "Unused.",
	"sendmany--result0":       "The transaction hash of the sent transaction.",

	// SendToAddressCmd help.
	"sendtoaddress--synopsis": "Authors, signs, and sends a transaction that outputs some amount to a payment address.\n" +
		"Unlike sendfrom, outputs are always chosen from the default account.\n" +
		"A change output is automatically included to send extra output value back to the original account.",
	"sendtoaddress-address":     "Address to pay.",
	"sendtoaddress-amount":      "Amount to send to the payment address valued in LBC.",
	"sendtoaddress-addresstype": "Address type filter for UTXOs to spent from. Must be one of 'legacy', 'p2sh-segwit', 'bech32', or '*'. Defaults to '*'.",
	"sendtoaddress-comment":     "Unused.",
	"sendtoaddress-commentto":   "Unused.",
	"sendtoaddress--result0":    "The transaction hash of the sent transaction.",

	// SetTxFeeCmd help.
	"settxfee--synopsis": "Modify the increment used each time more fee is required for an authored transaction.",
	"settxfee-amount":    "The new fee increment valued in LBC.",
	"settxfee--result0":  "The boolean 'true'.",

	// SignMessageCmd help.
	"signmessage--synopsis": "Signs a message using the private key of a payment address.",
	"signmessage-address":   "Payment address of private key used to sign the message with.",
	"signmessage-message":   "Message to sign.",
	"signmessage--result0":  "The signed message encoded as a base64 string.",

	// SignRawTransactionCmd help.
	"signrawtransaction--synopsis": "Signs transaction inputs using private keys from this wallet and request.\n" +
		"The valid flags options are ALL, NONE, SINGLE, ALL|ANYONECANPAY, NONE|ANYONECANPAY, and SINGLE|ANYONECANPAY.",
	"signrawtransaction-rawtx":    "Unsigned or partially unsigned transaction to sign encoded as a hexadecimal string.",
	"signrawtransaction-inputs":   "Additional data regarding inputs that this wallet may not be tracking.",
	"signrawtransaction-privkeys": "Additional WIF-encoded private keys to use when creating signatures.",
	"signrawtransaction-flags":    "Sighash flags.",

	// SignRawTransactionResult help.
	"signrawtransactionresult-hex":      "The resulting transaction encoded as a hexadecimal string.",
	"signrawtransactionresult-complete": "Whether all input signatures have been created.",
	"signrawtransactionresult-errors":   "Script verification errors (if exists).",

	// SignRawTransactionError help.
	"signrawtransactionerror-error":     "Verification or signing error related to the input.",
	"signrawtransactionerror-sequence":  "Script sequence number.",
	"signrawtransactionerror-scriptSig": "The hex-encoded signature script.",
	"signrawtransactionerror-txid":      "The transaction hash of the referenced previous output.",
	"signrawtransactionerror-vout":      "The output index of the referenced previous output.",

	// ValidateAddressCmd help.
	"validateaddress--synopsis": "Verify that an address is valid.\n" +
		"Extra details are returned if the address is controlled by this wallet.\n" +
		"The following fields are valid only when the address is controlled by this wallet (ismine=true): isscript, pubkey, iscompressed, account, addresses, hex, script, and sigsrequired.\n" +
		"The following fields are only valid when address has an associated public key: pubkey, iscompressed.\n" +
		"The following fields are only valid when address is a pay-to-script-hash address: addresses, hex, and script.\n" +
		"If the address is a multisig address controlled by this wallet, the multisig fields will be left unset if the wallet is locked since the redeem script cannot be decrypted.",
	"validateaddress-address": "Address to validate.",

	// ValidateAddressWalletResult help.
	"validateaddresswalletresult-isvalid":      "Whether or not the address is valid.",
	"validateaddresswalletresult-address":      "The payment address (only when isvalid is true).",
	"validateaddresswalletresult-ismine":       "Whether this address is controlled by the wallet (only when isvalid is true).",
	"validateaddresswalletresult-iswatchonly":  "Unset.",
	"validateaddresswalletresult-isscript":     "Whether the payment address is a pay-to-script-hash address (only when isvalid is true).",
	"validateaddresswalletresult-pubkey":       "The associated public key of the payment address, if any (only when isvalid is true).",
	"validateaddresswalletresult-iscompressed": "Whether the address was created by hashing a compressed public key, if any (only when isvalid is true).",
	"validateaddresswalletresult-account":      "The account this payment address belongs to (only when isvalid is true).",
	"validateaddresswalletresult-addresses":    "All associated payment addresses of the script if address is a multisig address (only when isvalid is true).",
	"validateaddresswalletresult-hex":          "The redeem script .",
	"validateaddresswalletresult-script":       "The class of redeem script for a multisig address.",
	"validateaddresswalletresult-sigsrequired": "The number of required signatures to redeem outputs to the multisig address.",

	// VerifyMessageCmd help.
	"verifymessage--synopsis": "Verify a message was signed with the associated private key of some address.",
	"verifymessage-address":   "Address used to sign message.",
	"verifymessage-signature": "The signature to verify.",
	"verifymessage-message":   "The message to verify.",
	"verifymessage--result0":  "Whether the message was signed with the private key of 'address'.",

	// WalletIsLockedCmd help.
	"walletislocked--synopsis": "Returns whether or not the wallet is locked.",
	"walletislocked--result0":  "Whether the wallet is locked.",

	// WalletLockCmd help.
	"walletlock--synopsis": "Lock the wallet.",

	// WalletPassphraseCmd help.
	"walletpassphrase--synopsis":  "Unlock the wallet.",
	"walletpassphrase-passphrase": "The wallet passphrase.",
	"walletpassphrase-timeout":    "The number of seconds to wait before the wallet automatically locks.",

	// WalletPassphraseChangeCmd help.
	"walletpassphrasechange--synopsis":     "Change the wallet passphrase.",
	"walletpassphrasechange-oldpassphrase": "The old wallet passphrase.",
	"walletpassphrasechange-newpassphrase": "The new wallet passphrase.",
}
