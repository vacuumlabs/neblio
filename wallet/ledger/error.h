#pragma once

#include <string>

namespace ledger {
	enum class ErrorCode {
		DEVICE_NOT_FOUND,
		DEVICE_OPEN_FAIL,
		DEVICE_DATA_SEND_FAIL,
		DEVICE_DATA_RECV_FAIL,
		APDU_INVALID_CMD,
		INVALID_TRUSTED_INPUT,
		UNRECOGNIZED_ERROR = 999,
	};

	class LedgerException : public std::exception {
	public:
		static std::string GetMessage(ErrorCode errorCode);

		LedgerException(ErrorCode errorCodeIn);
		~LedgerException() noexcept override = default;

		ErrorCode GetErrorCode() const;
		std::string GetMessage() const;

		const char *what() const noexcept override;
	private:
		ErrorCode errorCode;
	};
} // namespace ledger
