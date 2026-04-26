#include <gtest/gtest.h>

#include "../../app/lxpsvc/models/operations/io_operations.hpp"
#include "../../app/lxpsvc/contexts/execution_context.hpp"

#include <quill/Backend.h>
#include <quill/Frontend.h>
#include <quill/LogMacros.h>
#include <quill/sinks/FileSink.h>

#include <array>

using namespace linuxplorer::lxpsvc;

TEST(context_text, queue) {
	contexts::execution_context ctx;
	win32::unique_event_handle termination = ::CreateEventW(nullptr, true, false, nullptr);

	std::thread thd([&ctx, &termination]() {
		auto handles = std::to_array<::HANDLE>({
			ctx.get_task_event().get(),
			termination.get()
		});

		bool done = false;
		while (!done) {
			auto response = ::WaitForMultipleObjects(handles.size(), handles.data(), false, INFINITE);
			switch (response) {
			case WAIT_OBJECT_0:
			{
				auto task = ctx.dequeue_task();
				
				while (!task->done()) {
					auto request = task->fetch();
					switch (request.index()) {
					case 0:
						std::cout << std::to_underlying(std::get<models::requests::remote::creation_request>(request).get_type()) << std::endl;;
						break;
					case 1:
						std::cout << std::get<models::requests::remote::modification_request>(request).get_range().get_length() << std::endl;
						break;
					default:
						break;
					}
					task->transition(models::requests::request_result::permanent_failure);
				}

				break;
			}
			case WAIT_OBJECT_0 + 1:
				done = true;
				break;
			default:
				break;
			}
		}
	});


	auto task1 = std::make_unique<models::operations::creation_operation>("C:\\Users\\koNinja\\server", "home\\koninja\\c.md");
	auto task2 = std::make_unique<models::operations::modification_operation>("C:\\Users\\koNinja\\server", "home\\koninja\\c.md", linuxplorer::lxpsvc::models::requests::remote::modification_type::overwritten);

	ctx.enqueue_task(std::move(task1));
	ctx.enqueue_task(std::move(task2));

	std::this_thread::sleep_for(std::chrono::seconds(5));
	::SetEvent(termination.get());
	thd.join();
}