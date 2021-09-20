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
					<div class="col-12  col-lg-10">
						<div class="row align-items-center my-4">
							<div class="col">
								<h2 class="h3 mb-0 page-title">금융상담 게시판 관리</h2>
							</div>
							<div class="col-auto">
								<button type="button" class="btn btn-secondary">
									<span class="fe fe-trash fe-12 mr-2"></span>삭제
								</button>
								<button type="button" class="btn btn-primary">
									<span class="fe fe-filter fe-12 mr-2"></span>신규등록
								</button>
							</div>
						</div>
						<div class="row align-items-center mb-3 border-bottom no-gutters">
							<div class="col">
								<ul class="nav nav-tabs border-0" id="myTab" role="tablist">
									<li class="nav-item"><a class="nav-link active"
										id="home-tab"href="#home" role="tab" >최신순</a></li>
									<li class="nav-item"><a class="nav-link" id="profile-tab"
										href="${ pageContext.request.contextPath }/admin/board/hidden" role="tab">숨긴글</a></li>
								</ul>
							</div>
						</div>
						<!-- table -->
						
						<table class="table table-borderless table-hover">
							<thead>
								<tr>
									<th style="width: 5%">
										<div class="custom-control custom-checkbox">
											<input type="checkbox" class="custom-control-input" id="all">
											<label class="custom-control-label" for="all"></label>
										</div>
									</th>
									<th style="width: 10%">글번호</th>
									<th style="width: 45%">제목</th>
									<th style="width: 15%">글쓴이</th>
									<th style="width: 10%">글정보</th>
									<th style="width: 15%">등록일</th>
									<th style="width: 5%">처리</th>
								</tr>
							</thead>
							<tbody>
								<c:forEach items="${ list }" var="boardVO" varStatus="loop">
									<tr>
										<td>
											<div class="custom-control custom-checkbox">
												<input type="checkbox" class="custom-control-input"
													id="${ boardVO.num }"> <label
													class="custom-control-label" for="${ boardVO.title }"></label>
											</div>
										</td>
										<td>
											<p class="mb-0 text-muted">
												<strong>${ boardVO.num }</strong>
											</p>
										</td>
										<td>
											<p class="mb-0 text-muted">${ boardVO.title }</p>
										</td>
										<td>
											<p class="mb-0 text-muted">${ boardVO.writer }
										</td>
										<td class="text-muted"><small class="mb-0 text-muted">조회수:
												${ boardVO.viewCnt }</small><br> <small class="mb-0 text-muted">댓글수:
												${ boardVO.cmtCnt }</small></td>
										<td>${ boardVO.regDate }</td>
										<td>
											<button class="btn btn-sm dropdown-toggle more-horizontal"
												type="button" data-toggle="dropdown" aria-haspopup="true"
												aria-expanded="false">
												<span class="text-muted sr-only">Action</span>
											</button>
											<div class="dropdown-menu dropdown-menu-right">
												<a class="dropdown-item" href="#">숨기기</a> <a
													class="dropdown-item" href="#">삭제</a>
											</div>
										</td>
									</tr>
								</c:forEach>
							</tbody>
						</table>
					</div>
				<nav aria-label="Table Paging" class="my-3">
					<ul class="pagination justify-content-end mb-0">
						<li class="page-item"><a class="page-link" href="#">Previous</a></li>
						<li class="page-item active"><a class="page-link" href="#">1</a></li>
						<li class="page-item"><a class="page-link" href="#">2</a></li>
						<li class="page-item"><a class="page-link" href="#">3</a></li>
						<li class="page-item"><a class="page-link" href="#">Next</a></li>
					</ul>
				</nav>
				</div>
			</div>
			<!-- .col-12 -->
			<!-- .row -->
			<!-- .container-fluid -->
	</main></div>
	<!-- ======= Modals ======= -->
	<jsp:include page="/WEB-INF/views/admin/include/modals.jsp" />
	<!-- End Footer -->
	<!-- ======= Footer ======= -->
	<jsp:include page="/WEB-INF/views/admin/include/common-js.jsp" />
	<!-- End Footer -->
</body>
</html>