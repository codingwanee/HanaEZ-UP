<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!doctype html>
<html>
<head>
<!-- ======= Head ======= -->
<jsp:include page="/WEB-INF/views/admin/include/common-css.jsp" />
<!-- End head -->
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
								src="${ pageContext.request.contextPath }/resources/images/ad_branch.png">
						</div> --%>
						<div class="row align-items-center my-4">
							<div class="col">
								<h2 class="h3 mb-0 page-title">외국인 특화지점 목록</h2>
							</div>
							<div class="col-auto ">
								<a href="${pageContext.request.contextPath}/admin/branch/register"><button type="button" class="btn btn-primary">
									<span class="fe fe-plus fe-12 mr-2"></span>신규등록
								</button></a>
								<button type="button" class="btn btn-secondary">
									<span class="fe fe-trash fe-12 mr-2"></span>삭제
								</button>
							</div>
						</div>
						<!-- table -->
						<div class="card shadow">
							<div class="card-body">
								<table class="table table-borderless table-hover">
									<thead>
										<tr>
											<th>
												<div class="custom-control custom-checkbox">
													<input type="checkbox" class="custom-control-input"
														id="all"> <label class="custom-control-label"
														for="all"></label>
												</div>
											</th>
											<th>지점코드</th>
											<th>지점명</th>
											<th>주소</th>
											<th>연락처</th>
											<th>등록일</th>
											<th>처리</th>
										</tr>
									</thead>
									<tbody>
										<c:forEach items="${ branchList }" var="branchVO"
											varStatus="loop">
											<tr>
												<td>
													<div class="custom-control custom-checkbox">
														<input type="checkbox" class="custom-control-input"
															id="${ branchVO.bid }"> <label class="custom-control-label"
															for="${ branchVO.bid }"></label>
													</div>
												</td>
												<td>
													<p class="mb-0 text-muted">
														<strong>${ branchVO.bid }</strong>
													</p>
												</td>
												<td>
													<p class="mb-0 text-muted">
														<strong>${ branchVO.nameKo }</strong>
													</p> <small class="mb-0 text-muted">${ branchVO.nameEn }</small>
												</td>
												<td>
													<p class="mb-0 text-muted">${ branchVO.addrKoNew }</p> <small
													class="mb-0 text-muted">${ branchVO.addrEn }</small>
												</td>
												<td>
													<p class="mb-0 text-muted">
														<a href="#" class="text-muted">${ branchVO.tel }</a>
<%-- 													</p> <small class="mb-0 text-muted">${ branchVO.fax }</small> --%>
												</td>
												<td class="text-muted">${ branchVO.regDate }</td>
												<td><button
														class="btn btn-sm dropdown-toggle more-horizontal"
														type="button" data-toggle="dropdown" aria-haspopup="true"
														aria-expanded="false">
														<span class="text-muted sr-only">Action</span>
													</button>
													<div class="dropdown-menu dropdown-menu-right">
														<a class="dropdown-item" href="#">Edit</a> <a
															class="dropdown-item" href="#">Remove</a> <a
															class="dropdown-item" href="#">Assign</a>
													</div></td>
											</tr>
										</c:forEach>
									</tbody>
								</table>
							</div>
						</div>
						<nav aria-label="Table Paging" class="my-3">
							<ul class="pagination justify-content-end mb-0">
								<li class="page-item"><a class="page-link" href="#">Previous</a></li>
								<li class="page-item active"><a class="page-link" href="#">1</a></li>
<!-- 								<li class="page-item"><a class="page-link" href="#">2</a></li>
								<li class="page-item"><a class="page-link" href="#">3</a></li> -->
								<li class="page-item"><a class="page-link" href="#">Next</a></li>
							</ul>
						</nav>
					</div>
					<!-- .col-12 -->
				</div>
				<!-- .row -->
			</div>
		</main>
		<!-- .container-fluid -->
	</div>
	<!-- ======= Modals ======= -->
	<jsp:include page="/WEB-INF/views/admin/include/modals.jsp" />
	<!-- End Footer -->
	<!-- ======= Footer ======= -->
	<jsp:include page="/WEB-INF/views/admin/include/common-js.jsp" />
	<!-- End Footer -->
</body>
</html>