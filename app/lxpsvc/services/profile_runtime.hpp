#ifndef LINUXPLORER_LXPSVC_PROFILE_RUNTIME_HPP_
#define LINUXPLORER_LXPSVC_PROFILE_RUNTIME_HPP_

#include <util/config/profiles.hpp>

namespace linuxplorer::app::lxpsvc {
	class profile_runtime {
	private:
		const util::config::profile& m_profile;
	public:
		profile_runtime(const util::config::profile& profile);

		void abort();

		virtual ~profile_runtime();
	};
}

#endif // LINUXPLORER_LXPSVC_PROFILE_RUNTIME_HPP_