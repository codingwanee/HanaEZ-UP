<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta content="width=device-width, initial-scale=1.0" name="viewport">

<title>Welcome to HanaEZ UP</title>
<meta content="" name="descriptison">
<meta content="" name="keywords">
<script src="http://code.jquery.com/jquery-3.5.1.min.js"></script>

<link
	href="${ pageContext.request.contextPath }/resources/assets/img/favicon.png"
	rel="icon">

<!-- Google Fonts -->
<link
	href="https://fonts.googleapis.com/css?family=Open+Sans:300,300i,400,400i,600,600i,700,700i|Raleway:300,300i,400,400i,600,600i,700,700i"
	rel="stylesheet">

<!-- common css -->
<jsp:include page="/WEB-INF/views/home/include/common-css.jsp" />
<jsp:include page="/WEB-INF/views/admin/include/common-css.jsp" />

</head>
<body>

	<!-- ======= Header ======= -->
	<jsp:include page="/WEB-INF/views/home/include/header.jsp" />

	<!-- ======= Main ======= -->
	<div id="wrapper">
		<!-- ======= Board Section ======= -->
		<section id="board" class="container">
			<!-- 		<main role="main" class="main-content"> -->
			<div class="container-fluid">
				<div class="row justify-content-center">
					<div class="col-12">
						<h2 class="page-title"><spring:message code="board.bread.title"></spring:message></h2>
						<p class="card-text">
							<spring:message code="board.bread.text"></spring:message>
						</p>
						<div class="row my-4">
							<!-- Small table -->
							<div class="col-md-12">
								<div class="card shadow">
									<div class="card-body">
										<!-- table -->
										<div id="dataTable-1_wrapper"
											class="dataTables_wrapper dt-bootstrap4 no-footer">

											<div class="row">
												<div class="col-sm-12 col-md-5 align-right">
													<div id="dataTable-1_filter" class="dataTables_filter">
														<label>Search:<input type="search"
															class="form-control form-control-sm" placeholder=""
															aria-controls="dataTable-1"></label>
													</div>
												</div>
											</div>
											<div class="row">
												<div class="col-sm-12">
													<table class="table datatables dataTable no-footer"
														id="dataTable-1" role="grid"
														aria-describedby="dataTable-1_info">
														<thead>
															<tr role="row">
																<th class="sorting" tabindex="0"
																	aria-controls="dataTable-1" rowspan="1" colspan="1"
																	aria-label="#: activate to sort column ascending"
																	style="width: 5%;">#</th>
																<th class="sorting" tabindex="0"
																	aria-controls="dataTable-1" rowspan="1" colspan="1"
																	aria-label="Name: activate to sort column ascending"
																	style="width: 10%;">주제</th>
																<th class="sorting" tabindex="0"
																	aria-controls="dataTable-1" rowspan="1" colspan="1"
																	aria-label="Name: activate to sort column ascending"
																	style="width: 50%;">제목</th>
																<th class="sorting" tabindex="0"
																	aria-controls="dataTable-1" rowspan="1" colspan="1"
																	aria-label="Department: activate to sort column ascending"
																	style="width: 10%;">글쓴이</th>
																<th class="sorting" tabindex="0"
																	aria-controls="dataTable-1" rowspan="1" colspan="1"
																	aria-label="City: activate to sort column ascending"
																	style="width: 10%;">조회수</th>
																<th class="sorting" tabindex="0"
																	aria-controls="dataTable-1" rowspan="1" colspan="1"
																	aria-label="Date: activate to sort column ascending"
																	style="width: 15%;">등록날짜</th>
															</tr>
														</thead>
														<tbody>
															<c:forEach items="${ list }" var="vo">
																<tr role="row">
																	<td>${ vo.num }</td>
																	<td>${ vo.subject }</td>
																	<td><a href="${ pageContext.request.contextPath }/board/${ vo.num }">${ vo.title }</a></td>
																	<td>${ vo.writer }</td>
																	<td>${ vo.viewCnt }</td>
																	<td>${ vo.regDate }</td>
																</tr>
															</c:forEach>
														</tbody>
													</table>
												</div>
											</div>
											<div class="row">
												<div class="col-md-10">
													<div class="dataTables_paginate paging_simple_numbers"
														id="dataTable-1_paginate">
														<ul class="pagination">
															<li class="paginate_button page-item previous disabled"
																id="dataTable-1_previous"><a href="#"
																aria-controls="dataTable-1" data-dt-idx="0" tabindex="0"
																class="page-link">Previous</a></li>
															<li class="paginate_button page-item active"><a
																href="#" aria-controls="dataTable-1" data-dt-idx="1"
																tabindex="0" class="page-link">1</a></li>
															<li class="paginate_button page-item "><a href="#"
																aria-controls="dataTable-1" data-dt-idx="2" tabindex="0"
																class="page-link">2</a></li>
															<li class="paginate_button page-item next"
																id="dataTable-1_next"><a href="#"
																aria-controls="dataTable-1" data-dt-idx="3" tabindex="0"
																class="page-link">Next</a></li>
														</ul>
													</div>
												</div>
												<div class="col-md-2">
													<a href="${ pageContext.request.contextPath }/board/write"><button class="btn btn-outline-secondary">새글쓰기</button></a>
												</div>
											</div>
										</div>
									</div>
								</div>
							</div>
							<!-- simple table -->
						</div>
						<!-- end section -->
					</div>
					<!-- .col-12 -->
				</div>
				<!-- .row -->
			</div>
			<!-- .container-fluid -->
			<div class="modal fade modal-notif modal-slide" tabindex="-1"
				role="dialog" aria-labelledby="defaultModalLabel" aria-hidden="true">
				<div class="modal-dialog modal-sm" role="document">
					<div class="modal-content">
						<div class="modal-header">
							<h5 class="modal-title" id="defaultModalLabel">Notifications</h5>
							<button type="button" class="close" data-dismiss="modal"
								aria-label="Close">
								<span aria-hidden="true">×</span>
							</button>
						</div>
						<div class="modal-body">
							<div class="list-group list-group-flush my-n3">
								<div class="list-group-item bg-transparent">
									<div class="row align-items-center">
										<div class="col-auto">
											<span class="fe fe-box fe-24"></span>
										</div>
										<div class="col">
											<small><strong>Package has uploaded
													successfull</strong></small>
											<div class="my-0 text-muted small">Package is zipped
												and uploaded</div>
											<small class="badge badge-pill badge-light text-muted">1m
												ago</small>
										</div>
									</div>
								</div>
								<div class="list-group-item bg-transparent">
									<div class="row align-items-center">
										<div class="col-auto">
											<span class="fe fe-download fe-24"></span>
										</div>
										<div class="col">
											<small><strong>Widgets are updated
													successfull</strong></small>
											<div class="my-0 text-muted small">Just create new
												layout Index, form, table</div>
											<small class="badge badge-pill badge-light text-muted">2m
												ago</small>
										</div>
									</div>
								</div>
								<div class="list-group-item bg-transparent">
									<div class="row align-items-center">
										<div class="col-auto">
											<span class="fe fe-inbox fe-24"></span>
										</div>
										<div class="col">
											<small><strong>Notifications have been sent</strong></small>
											<div class="my-0 text-muted small">Fusce dapibus,
												tellus ac cursus commodo</div>
											<small class="badge badge-pill badge-light text-muted">30m
												ago</small>
										</div>
									</div>
									<!-- / .row -->
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
								</div>
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
			</div>
			<div class="modal fade modal-shortcut modal-slide" tabindex="-1"
				role="dialog" aria-labelledby="defaultModalLabel" aria-hidden="true">
				<div class="modal-dialog" role="document">
					<div class="modal-content">
						<div class="modal-header">
							<h5 class="modal-title" id="defaultModalLabel">Shortcuts</h5>
							<button type="button" class="close" data-dismiss="modal"
								aria-label="Close">
								<span aria-hidden="true">×</span>
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
										<i
											class="fe fe-upload-cloud fe-32 align-self-center text-white"></i>
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

		</section>
	</div>

	<!-- ======= Footer ======= -->
	<%@include file="/WEB-INF/views/home/include/footer.jsp"%>
	<jsp:include page="/WEB-INF/views/home/include/common-js.jsp" />
	<jsp:include page="/WEB-INF/views/admin/include/common-js.jsp" />
	<!-- End Footer -->
</body>
</html>