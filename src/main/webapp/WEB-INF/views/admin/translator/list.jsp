<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!doctype html>
<html>
<head>
<title>HanaEZ UP Admin Side</title>

<!-- ======= Head ======= -->
<jsp:include page="/WEB-INF/views/admin/include/common-css.jsp" />

<!-- Favicons -->
<link
	href="${ pageContext.request.contextPath }/resources/assets/img/favicon.png"
	rel="icon">

<script src="http://code.jquery.com/jquery-3.5.1.min.js"></script>
</head>
<body class="vertical  light  ">
	<div class="wrapper">

		<!-- ======= Aside Menubar ======= -->
		<jsp:include page="/WEB-INF/views/admin/include/aside.jsp" />
		<!-- Aside Menubar -->

		<main role="main" class="main-content">
			<div class="container-fluid">
				<div class="row justify-content-center">
					<div class="col-12 col-lg-10">
						<%-- 						<div class="row col-sm-12 justify-content-center">
							<img style="width: 40%"
								src="${ pageContext.request.contextPath }/resources/images/ad_translator.png">
						</div>					 --%>
						<div class="row align-items-center my-4">
							<div class="col">
								<h2 class="page-title">통역사 지원 목록</h2>
							</div>
							<div class="col-auto">
								<a
									href="${ pageContext.request.contextPath }/admin/translator/excel">
									<button type="button" class="btn btn-lg btn-primary">
										<span class="fe fe-download fe-16 mr-3">&nbsp;&nbsp;엑셀
											다운로드</span>
									</button>
								</a>
							</div>
						</div>
						<!-- .card-deck -->
						<div class="row align-items-center mb-3 border-bottom no-gutters">
							<div class="col">
								<ul class="nav nav-tabs border-0" id="myTab" role="tablist">
									<li class="nav-item"><a class="nav-link active"
										id="home-tab" data-toggle="tab" href="#home" role="tab"
										aria-controls="home" aria-selected="true">최신순</a></li>
									<li class="nav-item"><a class="nav-link" id="profile-tab"
										data-toggle="tab" href="#profile" role="tab"
										aria-controls="profile" aria-selected="false">활동중</a></li>
									<li class="nav-item"><a class="nav-link" id="contact-tab"
										data-toggle="tab" href="#contact" role="tab"
										aria-controls="contact" aria-selected="false">부적합</a></li>
								</ul>
							</div>
						</div>
						<!-- table -->
						<table class="table table-borderless table-striped">
							<thead>
								<tr>
									<td>
										<div class="custom-control custom-checkbox">
											<input type="checkbox" class="custom-control-input" id="all2">
											<label class="custom-control-label" for="all2"></label>
										</div>
									</td>
									<th style="width: 10%">언어</th>
									<th style="width: 15%">이름</th>
									<th style="width: 20%">연락처</th>
									<th style="width: 40%">자기소개</th>
									<th style="width: 10%">등록일</th>
									<th style="width: 5%">관리</th>
								</tr>
							</thead>
							<tbody>
								<c:forEach items="${ translatorList }" var="translatorVO"
									varStatus="loop">
									<tr>
										<td>
											<div class="custom-control custom-checkbox">
												<input type="checkbox" class="custom-control-input"
													id="2474"> <label class="custom-control-label"
													for="2474"></label>
											</div>
										</td>


										<%-- 활동여부
 												<c:choose>
													<c:when test="${ translatorVO.status eq '0'}">
														<td class="text-muted"><span
															class="badge badge-pill badge-success">검토대기</span></td>
													</c:when>
													<c:when test="${ translatorVO.status eq '1'}">
														<td class="text-muted"><span
															class="badge badge-pill badge-danger">활동중</span></td>
													</c:when>
													<c:otherwise>
														<td>부적합</td>
													</c:otherwise>
												</c:choose> --%>
										<td>
											<p class="mb-0 text-muted">
												<strong>${translatorVO.lang}</strong>
											</p>
										</td>
										<td>
											<p class="mb-0 text-muted">
												<strong>${translatorVO.firstName}</strong>
											</p> <small class="mb-0 text-muted">${translatorVO.lastName}</small>
										</td>

										<td>
											<p class="mb-0 text-muted">
												<a href="#" class="text-muted">${translatorVO.tel1} -
													${translatorVO.tel2} - ${translatorVO.tel3}</a>
											</p> <small class="mb-0 text-muted">${translatorVO.email}</small>
										</td>
										<td class="w-25"><small class="text-muted">
												${translatorVO.message} </small></td>
										<td class="text-muted">${translatorVO.regDate}</td>
										<td><button
												class="btn btn-sm dropdown-toggle more-horizontal"
												type="button" data-toggle="dropdown" aria-haspopup="true"
												aria-expanded="false">
												<span class="text-muted sr-only">Action</span>
											</button>
											<div class="dropdown-menu dropdown-menu-right">
												<a class="dropdown-item" href="#">검토중</a> <a
													class="dropdown-item" href="#">활동중</a> <a
													class="dropdown-item" href="#">활동중지</a>
											</div></td>
									</tr>
								</c:forEach>

							</tbody>
						</table>
						<nav aria-label="Table Paging" class="mb-0 text-muted">
							<ul class="pagination justify-content-center mb-0">
								<li class="page-item"><a class="page-link" href="#">Previous</a></li>
								<li class="page-item active"><a class="page-link" href="#">1</a></li>
								<!-- 										<li class="page-item"><a class="page-link"
											href="#">2</a></li>
										<li class="page-item"><a class="page-link" href="#">3</a></li> -->
								<li class="page-item"><a class="page-link" href="#">Next</a></li>
							</ul>
						</nav>
					</div>
				</div>
			</div>
			<!-- customized table -->
	</main>
	</div>
	<!-- end section -->

	<!-- ======= Footer ======= -->
	<jsp:include page="/WEB-INF/views/admin/include/common-js.jsp" />
	<!-- End Footer -->

</body>
</html>