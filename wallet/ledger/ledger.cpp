#include "ledger.h"
#include "error.h"
#include "hash.h"
#include "utils.h"
#include "base58.h"
#include "bip32.h"
#include "tx.h"
#include "wallet.h"

#include <algorithm>
#include <iostream>

namespace ledger
{
	Ledger::Ledger(Transport::TransportType transportType) { this->transport_ = std::unique_ptr<Transport>(new Transport(transportType)); }

	Ledger::~Ledger() { transport_->close(); }

	Error Ledger::open()
	{
		std::cout << "Opening Ledger connection." << std::endl;
		auto openError = transport_->open();
		if (openError != ledger::Error::SUCCESS)
		{
			throw ledger::error_message(openError);
		}
		std::cout << "Ledger connection opened." << std::endl;
	}

	std::tuple<bytes, std::string, bytes> Ledger::GetPublicKey(const std::string &path, bool confirm)
	{
		auto payload = bytes();

		auto pathBytes = bip32::ParseHDKeypath(path);
		payload.push_back(pathBytes.size() / 4);
		utils::AppendVector(payload, pathBytes);

		auto result = transport_->exchange(APDU::CLA, APDU::INS_GET_PUBLIC_KEY, confirm, 0x02, payload);
		auto err = std::get<0>(result);
		auto buffer = std::get<1>(result);
		if (err != Error::SUCCESS)
			throw error_message(err);

		auto offset = 1;
		auto pubKeyLen = (int)buffer[offset] * 16 + 1;
		auto pubKey = utils::Splice(buffer, offset, pubKeyLen);
		offset += pubKeyLen;

		auto addressLen = (int)buffer[offset];
		offset++;
		auto address = utils::Splice(buffer, offset, addressLen);
		offset += addressLen;

		auto chainCode = utils::Splice(buffer, offset, 32);
		offset += 32;

		if (offset != buffer.size())
			throw "Something went wrong";

		return {pubKey, std::string(address.begin(), address.end()), chainCode};
	}

	std::tuple<Error, bytes> Ledger::GetTrustedInputRaw(bool firstRound, uint32_t indexLookup, const bytes &transactionData)
	{
		auto result = transport_->exchange(APDU::CLA, APDU::INS_GET_TRUSTED_INPUT, firstRound ? 0x00 : 0x80, 0x00, transactionData);
		auto err = std::get<0>(result);
		auto buffer = std::get<1>(result);
		if (err != Error::SUCCESS)
			return {err, {}};

		return {err, bytes(buffer.begin(), buffer.end())};
	}

    std::tuple<Error, bytes> Ledger::GetTrustedInput(const CWalletTx& wtxNew, uint32_t indexLookup, Tx tx)
	{
		bytes serializedTransaction;
        utils::AppendUint32(serializedTransaction, tx.version, true);
        utils::AppendUint32(serializedTransaction, tx.time, true);
        // std::cout << "Serialized tx time: " << tx.time << std::endl;
        // std::cout << "Serialized WTX time: " << wtxNew.nTime << std::endl;
        // std::cout << "Serialized tx with time: " << ledger::utils::BytesToHex(serializedTransaction) << std::endl;

		utils::AppendVector(serializedTransaction, utils::CreateVarint(tx.inputs.size()));
		for (auto input : tx.inputs)
		{
			utils::AppendVector(serializedTransaction, input.prevout);
			utils::AppendVector(serializedTransaction, utils::CreateVarint(input.script.size()));
			utils::AppendVector(serializedTransaction, input.script);
			utils::AppendUint32(serializedTransaction, input.sequence);
		}

		utils::AppendVector(serializedTransaction, utils::CreateVarint(tx.outputs.size()));
		for (auto output : tx.outputs)
		{
			utils::AppendUint64(serializedTransaction, output.amount, true);
			utils::AppendVector(serializedTransaction, utils::CreateVarint(output.script.size()));
			utils::AppendVector(serializedTransaction, output.script);
		}

		utils::AppendUint32(serializedTransaction, tx.locktime);

		return GetTrustedInput(indexLookup, serializedTransaction);
	}

	std::tuple<Error, bytes> Ledger::GetTrustedInput(uint32_t indexLookup, const bytes &serializedTransaction)
	{
		auto MAX_CHUNK_SIZE = 255;
		std::vector<bytes> chunks;
		auto offset = 0;

		bytes data;
		utils::AppendUint32(data, indexLookup);

		utils::AppendVector(data, serializedTransaction);

		while (offset != data.size())
		{
			auto chunkSize = data.size() - offset > MAX_CHUNK_SIZE ? MAX_CHUNK_SIZE : data.size() - offset;
			chunks.push_back(utils::Splice(data, offset, chunkSize));
			offset += chunkSize;
		}

		auto isFirst = true;
		bytes finalResults;
		for (auto &chunk : chunks)
		{
			auto result = GetTrustedInputRaw(isFirst, 0, chunk);
			if (std::get<0>(result) != Error::SUCCESS)
			{
				return {std::get<0>(result), {}};
			}

			isFirst = false;
			finalResults = std::get<1>(result);
		}

		return {Error::SUCCESS, finalResults};
	}

	void Ledger::UntrustedHashTxInputFinalize(const CWalletTx wtxNew, const std::string &changePath)
	{
		auto ins = APDU::INS_UNTRUSTED_HASH_TRANSACTION_INPUT_FINALIZE;
		auto p2 = 0x00;

		auto p1 = 0xFF;
		if (changePath.length() > 0)
		{
			auto serializedChangePath = bip32::ParseHDKeypath(changePath);

			bytes changePathData;
			changePathData.push_back(serializedChangePath.size() / 4);
			utils::AppendVector(changePathData, serializedChangePath);

			auto result = transport_->exchange(APDU::CLA, ins, p1, p2, changePathData);
			auto err = std::get<0>(result);
			auto buffer = std::get<1>(result);
			if (err != Error::SUCCESS)
				throw err;
		}
		else
		{
			auto result = transport_->exchange(APDU::CLA, ins, p1, p2, {0x00});
			auto err = std::get<0>(result);
			auto buffer = std::get<1>(result);
			if (err != Error::SUCCESS)
				throw err;
		}

		p1 = 0x00;
        auto result = transport_->exchange(APDU::CLA, ins, p1, p2, utils::CreateVarint(wtxNew.vout.size()));
        auto err = std::get<0>(result);
        auto buffer = std::get<1>(result);
        if (err != Error::SUCCESS)
            throw err;

		for (auto i = 0; i < wtxNew.vout.size(); i++)
		{
			p1 = i < wtxNew.vout.size() - 1 ? 0x00 : 0x80;

			auto output = wtxNew.vout[i];
			bytes outputData;
            utils::AppendUint64(outputData, output.nValue, true);
            utils::AppendVector(outputData, utils::CreateVarint(output.scriptPubKey.size()));
			utils::AppendVector(outputData, output.scriptPubKey);

			auto result = transport_->exchange(APDU::CLA, ins, p1, p2, outputData);
			auto err = std::get<0>(result);
			auto buffer = std::get<1>(result);
			if (err != Error::SUCCESS)
				throw err;
		}
	}

	void Ledger::UntrustedHashTxInputStart(const CWalletTx wtxNew, const std::vector<TrustedInput> &trustedInputs, int inputIndex, bytes script, bool isNewTransaction)
	{
		auto ins = APDU::INS_UNTRUSTED_HASH_TRANSACTION_INPUT_START;
		auto p1 = 0x00;
		auto p2 = isNewTransaction ? 0x00 : 0x80;

		bytes data;
		utils::AppendUint32(data, wtxNew.nVersion, true);
		utils::AppendUint32(data, wtxNew.nTime, true);
		utils::AppendVector(data, utils::CreateVarint(trustedInputs.size()));

		auto result = transport_->exchange(APDU::CLA, ins, p1, p2, data);
		auto err = std::get<0>(result);
		auto buffer = std::get<1>(result);
		if (err != Error::SUCCESS)
			throw err;

		p1 = 0x80;
		for (auto i = 0; i < trustedInputs.size(); i++)
		{
			auto trustedInput = trustedInputs[i];
			auto _script = i == inputIndex ? script : bytes();

            auto input = wtxNew.vin[i];

            std::cout<<"trustedInput: " << ledger::utils::BytesToHex(trustedInput.serialized) << std::endl;
            std::cout<<"input prevout hash: " << ledger::utils::BytesToHex(std::vector<uint8_t>(input.prevout.hash.begin(), input.prevout.hash.end())) << std::endl;
            std::cout<<"input prevout n: " << input.prevout.n << std::endl;

			bytes _data;
			_data.push_back(0x01);
            _data.push_back(trustedInput.serialized.size());
			utils::AppendVector(_data, trustedInput.serialized);
			utils::AppendVector(_data, utils::CreateVarint(_script.size()));

			auto result = transport_->exchange(APDU::CLA, ins, p1, p2, _data);
			auto err = std::get<0>(result);
			auto buffer = std::get<1>(result);
			if (err != Error::SUCCESS)
				throw err;

			bytes scriptData;
			utils::AppendVector(scriptData, _script);
            utils::AppendUint32(scriptData, 0xffffffff, true);

			result = transport_->exchange(APDU::CLA, ins, p1, p2, scriptData);
			err = std::get<0>(result);
			buffer = std::get<1>(result);
			if (err != Error::SUCCESS)
				throw err;
		}
	}

    std::vector<std::tuple<int, bytes>> Ledger::SignTransaction(CWalletTx& wtxNew, const std::string& changePath, const std::vector<std::string> &signPaths, const std::vector<std::tuple<bytes, uint32_t>> &rawUtxos)
	{
		// Tx tx;
		// tx.version = 2;
		// tx.time = wtxNew.nTime;
        // tx.locktime = wtxNew.nLockTime;

		// build UTxOs and count amount available
		std::vector<Utxo> utxos;
		// uint64_t amountAvailable = 0;
		for (const auto &rawUtxo : rawUtxos)
		{
			Utxo utxo;
			utxo.raw = std::get<0>(rawUtxo);
			utxo.index = std::get<1>(rawUtxo);

            std::cout << "Raw UTxOTx: " << ledger::utils::BytesToHex(utxo.raw) << std::endl;

			auto utxoTx = ledger::DeserializeTransaction(utxo.raw);
			utxo.tx = utxoTx;

            std::cout << "UTxOTx time: " << utxo.tx.time << std::endl;

			utxos.push_back(utxo);

			// auto amount = utxoTx.outputs[utxo.index].amount;
			// amountAvailable += amount;
		}

		// get trusted inputs
		std::vector<TrustedInput> trustedInputs;
		std::vector<TxInput> inputs;
        std::vector<std::tuple<int, bytes>> signatures;
		for (auto i = 0; i < utxos.size(); i++)
		{
			const auto &utxo = utxos[i];

            const auto serializedTrustedInputResult = GetTrustedInput(wtxNew, utxo.index, utxo.tx);
            const auto serializedTrustedInput = std::get<1>(serializedTrustedInputResult);
            auto trustedInput = ledger::DeserializeTrustedInput(serializedTrustedInput);

			TxInput txInput;
			// txInput.prevout = trustedInput.prevTxId;

			// auto publicKeyResult = GetPublicKey(signPaths[i], false);
			// auto publicKey = utils::CompressPubKey(std::get<0>(publicKeyResult));

			// auto pubKeyHash = Hash160(publicKey);
			// bytes pubKeyHashVector(pubKeyHash.begin(), pubKeyHash.end());

			// bytes finalScriptPubKey;
			// finalScriptPubKey.push_back(0x76);
			// finalScriptPubKey.push_back(0xa9);
			// finalScriptPubKey.push_back(0x14);
			// utils::AppendVector(finalScriptPubKey, pubKeyHashVector);
			// finalScriptPubKey.push_back(0x88);
			// finalScriptPubKey.push_back(0xac);

			// txInput.script = finalScriptPubKey;
			// txInput.sequence = 0xfffffffd;

			// std::cout << "vin script sig: " << ledger::utils::BytesToHex(wtxNew.vin[i].scriptSig) << std::endl;
			// std::cout << "utxo script   : " << ledger::utils::BytesToHex(utxo.tx.outputs[utxo.index].script) << std::endl;
			// std::cout << "finalScriptPub: " << ledger::utils::BytesToHex(finalScriptPubKey) << std::endl;
			
            // CDataStream ssValue(SER_NETWORK, CLIENT_VERSION);
            // ssValue.reserve(10000);
            // ssValue << wtxNew.vin[i].prevout;

            // txInput.prevout = std::vector<uint8_t>(ssValue.begin(), ssValue.end());
        //    std::cout << "WtxNew " << i << " prevout: " << ledger::utils::BytesToHex(std::vector<uint8_t>(wtxNew.vin[i].prevout.hash.begin(), wtxNew.vin[i].prevout.hash.end()))<< std::endl;
           wtxNew.vin[i].prevout.hash = uint256(trustedInput.prevTxId);
           wtxNew.vin[i].prevout.n = trustedInput.outIndex;
           txInput.prevout = std::vector<uint8_t>(serializedTrustedInput.begin()+4,serializedTrustedInput.begin()+4+0x24);
            txInput.script = utxo.tx.outputs[utxo.index].script;
			txInput.sequence = wtxNew.vin[i].nSequence;


           std::cout << "WtxNew " << i << " prevout: " << ledger::utils::BytesToHex(std::vector<uint8_t>(wtxNew.vin[i].prevout.hash.begin(), wtxNew.vin[i].prevout.hash.end()))<< std::endl;
           std::cout << "tx " << i << " prevout: " << ledger::utils::BytesToHex(txInput.prevout)<< std::endl;

			trustedInputs.push_back(trustedInput);
            inputs.push_back(txInput);
		}

		// create change output
		// if (amountAvailable - fees > amount)
		// {
		// 	auto publicKeyResult = GetPublicKey(changePath, false);
		// 	auto publicKey = utils::CompressPubKey(std::get<0>(publicKeyResult));
		// 	auto publicKeyHash = Hash160(publicKey);

		// 	// TODO GK - other key structures?
		// 	bytes changeScriptPublicKey;
		// 	changeScriptPublicKey.push_back(0x76);
		// 	changeScriptPublicKey.push_back(0xa9);
		// 	changeScriptPublicKey.push_back(0x14);
		// 	utils::AppendVector(changeScriptPublicKey, bytes(publicKeyHash.begin(), publicKeyHash.end()));
		// 	changeScriptPublicKey.push_back(0x88);
		// 	changeScriptPublicKey.push_back(0xac);

        //     TxOutput txChangeOutput;
        //     txChangeOutput.amount = amountAvailable - amount - fees;
		// 	txChangeOutput.script = changeScriptPublicKey;
		// 	tx.outputs.push_back(txChangeOutput);
		// }

		// // create output to address
		// // TODO GK - other key structures?
		// bytes scriptPublicKey;
		// scriptPublicKey.push_back(0x76);
		// scriptPublicKey.push_back(0xa9);
		// scriptPublicKey.push_back(0x14);
		// auto addressDecoded = Base58Decode(address);
		// utils::AppendVector(scriptPublicKey, bytes(addressDecoded.begin() + 1, addressDecoded.end() - 4));
		// scriptPublicKey.push_back(0x88);
		// scriptPublicKey.push_back(0xac);


		// for (const auto &vout:wtxNew.vout)
		// {
		// 	TxOutput txOutput;
		// 	txOutput.amount = vout.nValue;
		// 	txOutput.script = vout.scriptPubKey;
		// 	tx.outputs.push_back(txOutput);
		// }

		// TxOutput txOutput;
		// txOutput.amount = amount;
		// txOutput.script = scriptPublicKey;
		// tx.outputs.push_back(txOutput);

		// TODO GK - refactor to use wtxNew
		for (auto i = 0; i < inputs.size(); i++)
		{
			std::cout << "Input " << i << " prevout: " << ledger::utils::BytesToHex(inputs[i].prevout)<< std::endl;
			std::cout << "Input " << i << " script: " << ledger::utils::BytesToHex(inputs[i].script)<< std::endl;
			std::cout << "Input " << i << " sequence: " << inputs[i].sequence<< std::endl;

			std::cout << "WtxNew " << i << " prevout: " << ledger::utils::BytesToHex(std::vector<uint8_t>(wtxNew.vin[i].prevout.hash.begin(), wtxNew.vin[i].prevout.hash.end()))<< std::endl;
			std::cout << "WtxNew " << i << " script: " << ledger::utils::BytesToHex(wtxNew.vin[i].scriptSig)<< std::endl;
			std::cout << "WtxNew " << i << " sequence: " << wtxNew.vin[i].nSequence << std::endl;
            UntrustedHashTxInputStart(wtxNew, trustedInputs, i, inputs[i].script, i == 0);
//        }

        UntrustedHashTxInputFinalize(wtxNew, changePath);

//        for (auto i = 0; i < inputs.size(); i++)
//        {
//            UntrustedHashTxInputStart(wtxNew, {trustedInputs[i]}, 0, inputs[i].script, false);

			auto ins = INS_UNTRUSTED_HASH_SIGN;
			auto p1 = 0x00;
			auto p2 = 0x00;

			auto serializedChangePath = bip32::ParseHDKeypath(signPaths[i]);

			bytes data;
			data.push_back(serializedChangePath.size() / 4);
			utils::AppendVector(data, serializedChangePath);
			data.push_back(0x00);
			utils::AppendUint32(data, wtxNew.nLockTime);
			data.push_back(0x01);

			auto result = transport_->exchange(APDU::CLA, ins, p1, p2, data);
			auto err = std::get<0>(result);
			auto buffer = std::get<1>(result);
			if (err != Error::SUCCESS)
				throw err;

			if (buffer[0] & 0x01)
			{
				bytes data;
				data.push_back(0x30);
				utils::AppendVector(data, bytes(buffer.begin() + 1, buffer.end()));
				signatures.push_back({1, data});
			}
			else
			{
				signatures.push_back({0, buffer});
			}
		}

		return signatures;
	}

	void Ledger::close() { return transport_->close(); }
} // namespace ledger
