#ifndef CREDENTIALS_HPP
#define CREDENTIALS_HPP

#include <util/config/app_settings.hpp>
#include <string>
#include <string_view>

namespace linuxplorer::util::config {
	class cryptographic_exception : public std::runtime_error {
	public:
		cryptographic_exception(const char* what) : std::runtime_error(what) {}
		cryptographic_exception(const std::string& what) : std::runtime_error(what) {}
	};

	class credential_info {
	private:
		std::wstring m_host;
		std::wstring m_username;
		std::wstring m_password;
	public:
		credential_info(std::wstring_view host, std::wstring_view username, std::wstring_view password) : m_host(host), m_username(username), m_password(password) {}
		credential_info(const credential_info& lhs) = default;
		credential_info(credential_info&& rhs) = default;
		credential_info& operator=(const credential_info& lhs) = default;
		credential_info& operator=(credential_info&& rhs) = default;

		inline std::wstring_view get_host() const noexcept {
			return this->m_host;
		}
		inline std::wstring_view get_username() const noexcept {
			return this->m_username;
		}
		inline std::wstring_view get_password() const noexcept {
			return this->m_password;
		}
	};

	inline std::byte* to_byte_ptr(unsigned char* ptr) {
		return reinterpret_cast<std::byte*>(ptr);
	}
	inline const std::byte* to_byte_ptr(const unsigned char* ptr) {
		return reinterpret_cast<const std::byte*>(ptr);
	}
	inline unsigned char* to_byte_ptr(std::byte* ptr) {
		return reinterpret_cast<unsigned char*>(ptr);
	}
	inline const unsigned char* to_byte_ptr(const std::byte* ptr) {
		return reinterpret_cast<const unsigned char*>(ptr);
	}

	class credential_config : public app_mtconfig<credential_info, std::string> {
	public:
		using data_type = credential_info;
		using json_data_type = std::string;
		credential_config();
	private:
		struct hlocal_delete_t {
		public:
			void operator()(void* ptr);
		};

		template <class T>
		using unique_hlocal_ptr_t = std::unique_ptr<std::remove_pointer_t<T>, hlocal_delete_t>;

		inline static constexpr std::size_t bytes_aes_block_length = 16;
		inline static constexpr std::size_t bytes_key_length = 32;
		inline static constexpr std::size_t bytes_iv_length = 16;

		static void decode_from_base64(std::string_view base64_data, std::unique_ptr<std::byte[]>& encoded, std::size_t& encoded_length);
		static void divide_decoded_raw_cred_into_elements(
			const std::byte* decoded_raw_cred,
			std::size_t decoded_raw_cred_length,
			const std::byte** encrypted_key_head,
			std::size_t* encrypted_key_length,
			const std::byte** iv_head,
			std::size_t* iv_length,
			const std::byte** encrypted_cred_data_head,
			std::size_t* encrypted_cred_data_length
		);
		static void decrypt_key(const std::byte* encrypted_key, std::size_t encrypted_key_length, unique_hlocal_ptr_t<std::byte>& decrypted_key, std::size_t& decrypted_key_length);

		static void decrypt_cred_data(
			const std::byte* encrypted_cred_data,
			std::size_t encrypted_cred_data_length,
			const std::byte* key,
			std::size_t key_length,
			const std::byte* iv,
			std::size_t iv_length,
			std::unique_ptr<std::byte[]>& decrypted_cred_data,
			std::size_t& decrypted_cred_data_length
		);

		static credential_info deserialize_cred_info_from_bin_to_obj(const std::byte* cred_data, std::size_t cred_data_length);

		static void serialize_cred_info_from_obj_to_bin(const data_type& data, std::unique_ptr<std::byte[]>& bin, std::size_t& bin_length);

		static void encrypt_cred_data(
			const std::byte* cred_data,
			std::size_t cred_data_length,
			std::unique_ptr<std::byte[]>& key,
			std::size_t& key_length,
			std::unique_ptr<std::byte[]>& iv,
			std::size_t& iv_length,
			std::unique_ptr<std::byte[]>& encrypted_cred_data,
			std::size_t& encrypted_cred_data_length
		);

		static void encrypt_key(const std::byte* key, std::size_t key_length, unique_hlocal_ptr_t<std::byte>& encrypted_key, std::size_t& encrypted_key_length);

		static void concatenate_cred_data(
			const std::byte* encrypted_key,
			std::size_t encrypted_key_length,
			const std::byte* iv,
			std::size_t iv_length,
			const std::byte* encrypted_cred_data,
			std::size_t encrypted_cred_data_length,
			std::unique_ptr<std::byte[]>& result,
			std::size_t& result_length
		);

		static void encode_to_base64(const std::byte* plain, std::size_t plain_length, std::string& encoded);

		data_type m_data;
	protected:
		virtual void xload(const json_data_type& data) override;
		virtual json_data_type xsave() const override;
		virtual data_type xget() const override;
		virtual void xset(const data_type& data) override;

		virtual inline constexpr std::string_view get_json_key_name() const noexcept override {
			return "cred";
		}
	};
}

#endif // CREDENTIALS_HPP