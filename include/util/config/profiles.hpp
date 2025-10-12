#ifndef LINUXPLORER_PROFILES_HPP_
#define LINUXPLORER_PROFILES_HPP_

#include <util/config/configfwd.hpp>
#include <util/config/app_settings.hpp>

#include <vector>
#include <shared_mutex>
#include <optional>

namespace linuxplorer::util::config {
	class LINUXPLORER_CONFIG_API openssl_category : public std::error_category {
	public:
		virtual const char* name() const noexcept override;
		virtual std::string message(int errc) const override;
	};

	class cryptographic_exception : public config_exception {
	private:
		std::error_code m_errc;
	public:
		explicit cryptographic_exception(const std::error_code& errc, const char* what) : config_exception(what), m_errc(errc) {}
		explicit cryptographic_exception(const std::error_code& errc, const std::string& what) : config_exception(what), m_errc(errc) {}
		virtual ~cryptographic_exception() noexcept = default;

		const std::error_code& code() const noexcept { return this->m_errc; }
	};

	class LINUXPLORER_CONFIG_API credential {
	private:
		std::wstring m_host;
		std::wstring m_username;
		std::wstring m_password;
	public:
		credential(std::wstring_view host, std::wstring_view username, std::wstring_view password) : m_host(host), m_username(username), m_password(password) {}

		inline std::wstring_view get_host() const noexcept {
			return this->m_host;
		}
		inline std::wstring_view get_username() const noexcept {
			return this->m_username;
		}
		inline std::wstring_view get_password() const noexcept {
			return this->m_password;
		}

		inline void set_host(std::wstring_view host) noexcept {
			this->m_host = host;
		}

		inline void set_username(std::wstring_view name) noexcept {
			this->m_username = name;
		}

		inline void set_password(std::wstring_view password) noexcept {
			this->m_password = password;
		}

		~credential() noexcept;
	};

	class LINUXPLORER_CONFIG_API profile {
	private:
		std::wstring m_name;
		credential m_credential;
		std::wstring m_syncroot;
		std::uint16_t m_port;
	public:
		profile(std::wstring_view name, std::wstring_view syncroot, std::uint16_t port, const credential& credential) : m_name(name), m_port(port), m_syncroot(syncroot), m_credential(credential) {}

		inline credential& get_credential() noexcept {
			return this->m_credential;
		};
		inline const credential& get_credential() const noexcept {
			return this->m_credential;
		}
		inline void set_credential(const credential& credential) noexcept {
			this->m_credential = credential;
		}

		inline const std::wstring_view get_syncroot() const noexcept {
			return this->m_syncroot;
		}
		inline void set_syncroot(std::wstring_view syncroot) noexcept {
			this->m_syncroot = syncroot;
		}

		inline const std::uint16_t get_port() const noexcept {
			return this->m_port;
		}
		inline void set_port(std::uint16_t port) noexcept {
			this->m_port = port;
		}

		inline std::wstring_view get_name() const noexcept {
			return this->m_name;
		}
		inline void set_name(std::wstring_view name) noexcept {
			this->m_name = name;
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

	class LINUXPLORER_CONFIG_API profile_config : public app_mtconfig<std::reference_wrapper<const std::vector<profile>>, nlohmann::json::array_t> {
	public:
		using actual_data_type = std::vector<profile>;
		using data_type = std::reference_wrapper<const actual_data_type>;
		using json_data_type = nlohmann::json::array_t;
		profile_config();

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

		static credential deserialize_cred_info_from_bin_to_obj(const std::byte* cred_data, std::size_t cred_data_length);

		static void serialize_cred_info_from_obj_to_bin(const credential& data, std::unique_ptr<std::byte[]>& bin, std::size_t& bin_length);

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

		actual_data_type m_data;
	protected:
		virtual void xload(const json_data_type& data) override;
		virtual json_data_type xsave() const override;
		virtual data_type xget() const override;
		virtual void xset(const data_type& data) override;

		virtual inline constexpr std::string_view get_json_key_name() const noexcept override {
			return "profiles";
		}
		virtual inline std::optional<json_data_type> get_default_value() const noexcept override {
			return json_data_type{};
		}
	};

	class profile_name_exception : public config_exception {
	private:
		std::wstring m_name;
	public:
		profile_name_exception(const std::wstring& name, const char* what) : config_exception(what), m_name(name) {}
		profile_name_exception(const std::wstring& name, const std::string& what) : config_exception(what), m_name(name) {}

		inline std::wstring_view get_name() const noexcept {
			return this->m_name;
		}
	};

	class LINUXPLORER_CONFIG_API profile_manager final {
	private:
		inline static profile_config s_config;
		inline static std::shared_mutex s_mutex;
		inline static std::optional<std::vector<profile>> s_profiles = std::nullopt;;

		static void internal_try_fetch();
	public:
		profile_manager() = delete;
		profile_manager(const profile_manager&) = delete;
		profile_manager(profile_manager&&) = delete;
		~profile_manager() = delete;

		static const std::vector<profile>& enumerate();
		static void add(const profile& profile);
		static void remove(std::wstring_view name);
		static profile& get(std::wstring_view name);

		static void flush();
		static void fetch();
	};
}

#endif // LINUXPLORER_PROFILES_HPP_