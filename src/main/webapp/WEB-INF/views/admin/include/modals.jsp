<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!-- .container-fluid -->
<div class="modal fade modal-notif modal-slide" tabindex="-1"
	role="dialog" aria-labelledby="defaultModalLabel" aria-hidden="true">
	<div class="modal-dialog modal-sm" role="document">
		<div class="modal-content">
			<div class="modal-header">
				<h5 class="modal-title" id="defaultModalLabel">알림</h5>
				<button type="button" class="close" data-dismiss="modal"
					aria-label="Close">
					<span aria-hidden="true">&times;</span>
				</button>
			</div>
			<div class="modal-body">
				<div class="list-group list-group-flush my-n3">
					<div class="list-group-item bg-transparent">
						<div class="row align-items-center">
							<div class="col-auto">
								<span class="fe fe-shield fe-24"></span>
							</div>
							<div class="col">
								<small><strong>새로 접수된 비대면 인증 신청내역</strong></small>
								<div class="my-0 text-muted small">
									미처리 건수가 <span id="certify-count">${count}</span>건 있습니다.
								</div>
								<a
									href="${ pageContext.request.contextPath }/admin/certify/list">
									<small
									class="badge badge-pill badge-success text-muted">바로가기</small></a>
							</div>
						</div>
					</div>
					<div class="list-group-item bg-transparent">
						<div class="row align-items-center">
							<div class="col-auto">
								<span class="fe fe-user fe-24"></span>
							</div>
							<div class="col">
								<small><strong>새로 접수된 통역사 신청내역</strong></small>
								<div class="my-0 text-muted small">
									미처리 건수가 <span id="certify-count">8</span>건 있습니다.
								</div>
								<a
									href="${ pageContext.request.contextPath }/admin/certify/list"><small
									class="badge badge-pill badge-success text-muted">바로가기</small></a>
							</div>
						</div>
					</div>
				</div>
<!-- 				<div class="list-group-item bg-transparent">
					<div class="row align-items-center">
						<div class="col-auto">
							<span class="fe fe-layout fe-24"></span>
						</div>
						<div class="col">
							<small><strong>Notifications have been sent</strong></small>
							<div class="my-0 text-muted small">Fusce dapibus, tellus ac
								cursus commodo</div>
							<small class="badge badge-pill badge-light text-muted">30m
								ago</small>
						</div>
					</div>
					/ .row
				</div>
				<div class="list-group-item bg-transparent">
					<div class="row align-items-center">
						<div class="col-auto">
							<span class="fe fe-link fe-24"></span>
						</div>
						<div class="col">
							<small><strong>Link was attached to menu</strong></small>
							<div class="my-0 text-muted small">New layout has been
								attached to the menu</div>
							<small class="badge badge-pill badge-light text-muted">1h
								ago</small>
						</div>
					</div>
				</div> -->
				<!-- / .row -->
			</div>
			<!-- / .list-group -->
		</div>
		<div class="modal-footer">
			<button type="button" class="btn btn-secondary btn-block"
				data-dismiss="modal">Clear All</button>
		</div>
	</div>
</div>
<div class="modal fade modal-shortcut modal-slide" tabindex="-1"
	role="dialog" aria-labelledby="defaultModalLabel" aria-hidden="true">
	<div class="modal-dialog" role="document">
		<div class="modal-content">
			<div class="modal-header">
				<h5 class="modal-title" id="defaultModalLabel">Shortcuts</h5>
				<button type="button" class="close" data-dismiss="modal"
					aria-label="Close">
					<span aria-hidden="true">&times;</span>
				</button>
			</div>
			<div class="modal-body px-5">
				<div class="row align-items-center">
					<div class="col-6 text-center">
						<div class="squircle bg-success justify-content-center">
							<i class="fe fe-cpu fe-32 align-self-center text-white"></i>
						</div>
						<p>Control area</p>
					</div>
					<div class="col-6 text-center">
						<div class="squircle bg-primary justify-content-center">
							<i class="fe fe-activity fe-32 align-self-center text-white"></i>
						</div>
						<p>Activity</p>
					</div>
				</div>
				<div class="row align-items-center">
					<div class="col-6 text-center">
						<div class="squircle bg-primary justify-content-center">
							<i class="fe fe-droplet fe-32 align-self-center text-white"></i>
						</div>
						<p>Droplet</p>
					</div>
					<div class="col-6 text-center">
						<div class="squircle bg-primary justify-content-center">
							<i class="fe fe-upload-cloud fe-32 align-self-center text-white"></i>
						</div>
						<p>Upload</p>
					</div>
				</div>
				<div class="row align-items-center">
					<div class="col-6 text-center">
						<div class="squircle bg-primary justify-content-center">
							<i class="fe fe-users fe-32 align-self-center text-white"></i>
						</div>
						<p>Users</p>
					</div>
					<div class="col-6 text-center">
						<div class="squircle bg-primary justify-content-center">
							<i class="fe fe-settings fe-32 align-self-center text-white"></i>
						</div>
						<p>Settings</p>
					</div>
				</div>
			</div>

		</div>
	</div>
</div>