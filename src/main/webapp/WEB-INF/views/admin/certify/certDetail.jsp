<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<!doctype html>
<html>
<head>
<title>HanaEZ UP Admin Side</title>

<!-- ======= Head ======= -->
<jsp:include page="/WEB-INF/views/admin/include/common-css.jsp" />

<!-- Favicons -->
<link href="${ pageContext.request.contextPath }/resources/assets/img/favicon.png" rel="icon">

<style>
.detectedTxt {
	background-color: #F9FFFF;
	color: #5c5c5c;
	border: 1px solid #BEE6E1;
	border-radius: 0.25rem;
	padding: 0.375rem 0.75rem;
	min-height: 120px;
}

#approval-btn, #denial-btn {
	width: 45%;
}

</style>

</head>
<body class="vertical  light  ">
	<div class="wrapper">
		<!-- ======= Aside Menubar ======= -->
		<jsp:include page="/WEB-INF/views/admin/include/aside.jsp" />
		<!-- Aside Menubar -->

		<main role="main" class="main-content">
			<div class="container-fluid justify-content-center align-items-center">
				<div class="row justify-content-center align-items-center">
					<div class="col-12 col-lg-10">
						<div class="row align-items-center my-4">
							<div class="col">
								<h2 class="page-title">비대면인증 신청정보 조회</h2>
							</div>
						</div>
						<div class="row">
							<div class="col-md-3 text-center mb-5">
								<div class="avatar avatar-xl">
									<img
										src="${ pageContext.request.contextPath }/resources/images/auth.png"
										alt="..." class="avatar-img rounded-circle">
								</div>
							</div>
							<div class="col-md-9">
								<div class="row align-items-center">
									<div class="col-md-7">
										<h4 class="mb-1">${ certHistoryVO.applicantNm }</h4>
										<p class="small mb-3">
											<span class="badge badge-dark">${ certHistoryVO.applicantNtnKo }
												/ ${ certHistoryVO.applicantNtnEn }</span>
										</p>
									</div>
								</div>
								<div class="row mb-4">
									<div class="col-md-10">
										<table class="table border-0">
											<tr>
												<th>ID</th>
												<td>${certHistoryVO.applicantId}</td>
												<th>국적</th>
												<td>${certHistoryVO.applicantNtnKo}(${certHistoryVO.applicantNtnEn})</td>
											</tr>
											<tr>
												<th>이름</th>
												<td>${certHistoryVO.applicantNm}</td>
												<th>가입일자</th>
												<td>${certHistoryVO.regDate}</td>
											</tr>
										</table>
									</div>
								</div>
							</div>
						</div>

						<div class="row mb-5">
							<div class="container-fluid">
								<div class="row justify-content-center">
									<div class="col-12 ">
										<!--  col-lg-10 col-xl-8  -->
										<div class="row align-items-center mb-4">
											<div class="col">
												<h2 class="h5 page-title">
													<small class="text-muted text-uppercase">신청번호</small><br />${ certHistoryVO.certId }</h2>
											</div>
											<div class="col-auto">
												<button type="button" class="btn btn-secondary">Print</button>
												<button type="button" class="btn btn-primary">List</button>
											</div>
										</div>
										<div class="card shadow">
											<div class="card-body p-5 align-items-center">
												<div class="row mb-5">
													<div class="col-12 text-center mb-4">
														<h2 class="mb-1 hanaM">신 청 서</h2>
														<p class="text-muted">
															Certification Apply Form<br /> Hana Bank.
														</p>
													</div>
													<div class="col-md-6 text-center" style="margin: 0px auto;">
														<img
															src="${ pageContext.request.contextPath }/resources/images/regcards/regcard1.jpg"
															class="navbar-brand-img mx-auto mb-4 w-100 justify-content-center align-items-center" alt="...">
													</div>
													<!-- 
													<div class="col-md-6">
														<p class="small text-muted text-uppercase mb-2"></p>
														<p class="mb-4">
															<strong>신청자: </strong> ${applicantVO.name} <br /> <strong>국적:
															</strong> ${certHistoryVO.applicantNtnKo}
															(${certHistoryVO.applicantNtnEn}) <br /> <strong>주소:
															</strong> ${applicantVO.addr1}<br>${applicantVO.addr2}<br />
															<strong>연락처: </strong>${applicantVO.contact} <br />
														</p>
														<p>
															<small class="small text-muted text-uppercase"></small> <strong>신청일:
															</strong>${certHistoryVO.regDate}
														</p>
													</div>
													 -->
												</div>
												<div class="row mb-5 align-items-center justify-content-center">
													<div class="col-4">
														<button type="button" id="approval-btn"
															class="btn btn-info">승인</button>
														<a href="#deny-reason" data-toggle="modal"><button id="denial-btn"
																class="btn btn-danger">거절</button></a>
													</div>
												</div>
												<!-- /.row -->
												<div class="row col-12 mb-3">
													<div id="approval-form" style="display: none;">
														<div class="card-header">
														<strong class="card-title">필수정보 입력</strong>
														</div>
															<div class="row col-12 mt-3">
																<div class="col-md-6">
																	<div class="form-group mb-6">
																		<label for="example-readonly">가입시 외국인 등록번호</label> <input
																			type="text" id="rgd-regNum"
																			class="form-control" disabled=""
																			value="${ applicantVO.socialNum }">
																	</div>
																	<div class="form-group mb-6">
																		<label for="example-disable">가입시 성명</label> <input
																			type="text" class="form-control" id="rgd-name"
																			disabled="" value="${ applicantVO.name }">
																	</div>
																	<div class="form-group mb-6">
																		<label for="example-disable">가입시 국가</label> <input
																			type="text" class="form-control" id="rgd-nationality"
																			disabled="" value="${ applicantVO.nationality }">
																	</div>
																	<div class="info01 text-muted mt-2">
																		<label for="example-disable"><strong>이미지에서 자동으로 추출된 텍스트입니다.(참고용)</strong></label>
																		<p class="detectedTxt">																																		
																		${ detectedStr }</p>
																	</div>
																</div>
																<!-- /.col -->
																<div class="col-md-6">
																	<div class="form-group mb-6">
																		<label for="regNum">외국인 등록번호 입력&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="label-regNum"></span></label> <input
																			type="text" name="regNum" id="regNum" class="form-control"
																			placeholder="000000-0000000">
																	</div>
																	<div class="form-group mb-6">
																		<label for="example-email">성명 입력&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="label-name"></span></label> <input
																			type="text" id="name" name="name"
																			class="form-control" placeholder="외국인 등록증 상 그대로 입력(미들네임 포함)">
																	</div>
																	<div class="form-group mb-6">
																		<label for="example-password">국가지역 입력&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="label-nationality"></span></label> <input
																			type="text" id="nationality" name="nationality"
																			class="form-control" placeholder="대문자로 입력">
																	</div>
																	<div class="form-group mb-6">
																		<label for="example-palaceholder">체류자격 입력</label> <select
																			name="visa" class="form-control">
																			<option value="A1">외교(A-1)</option>
																			<option value="A2">공무(A-2)</option>
																			<option value="C4">단기취업(C-4)</option>
																			<option value="D2">유학(D-2)</option>
																			<option value="D10">구직(D-10)</option>
																			<option value="D7">주재(D-7)</option>
																			<option value="F2">거주(F-2)</option>
																			<option value="F6">결혼이민(F-6)</option>
																			<option value="H1">관광취업(H-1)</option>
																		</select>
																	</div>
																	<div class="form-group mb-6">
																		<label for="example-palaceholder">발급일자 입력</label> <input
																			type="text" id="example-palaceholder"
																			class="form-control" placeholder="YYYY.MM.DD 형식">
																		<!-- <span
																					class="help-block"><small>A block of
																						help text that breaks onto a new line.</small></span>
 																					-->
																	</div>
																</div>
															</div>
														</div>
													</div>
												<div class="row mt-5">
													<div class="col-12">
														<strong class="card-title mb-3">동일인의 지난 신청내역</strong>
														<table class="table table-borderless">
															<thead>
																<tr role="row">
																	<th>신청번호</th>
																	<th>신청일자</th>
																	<th>거부사유</th>
																	<th>처리현황</th>
																</tr>
															</thead>
															<tbody>
																<c:forEach items="${ certHistoryList }" var="listVO">
																	<tr>
																		<td scope="col">${listVO.certId}</td>
																		<td>${ listVO.regDate }</td>
																		<td>${ listVO.reason }</td>
																		<td><span class="dot dot-lg bg-warning mr-2"></span>Due</td>
																	</tr>
																</c:forEach>
															</tbody>
														</table>
													</div>
												</div>
											</div>
											<!-- /.card-body -->
										</div>
										<!-- /.card -->
									</div>
									<!-- /.col-12 -->
								</div>
								<!-- .row -->
							</div>
						</div>
						<!-- .row -->
					</div>
				</div>
			</div>
		</main>
	</div>
	<!-- ======= Modals ======= -->
	<jsp:include page="/WEB-INF/views/admin/include/modals.jsp" />
	<!-- ======= Footer ======= -->
	<jsp:include page="/WEB-INF/views/admin/include/common-js.jsp" />
	<!-- End Footer -->

	<div class="modal fade" id="deny-reason">
		<div class="modal-dialog">
			<div class="modal-content">
				<!-- header -->
				<div class="modal-header">
					<!-- header title -->
					<h4 class="modal-title">거부 사유 입력</h4>
					<!-- 닫기(x) 버튼 -->
					<button type="button" class="close" data-dismiss="modal">×</button>
				</div>
				<!-- body -->
				<form method="post"
					action="${ pageContext.request.contextPath }/admin/certify/denial">
					<div class="modal-body">
						<div class="container">
							<div class="row d-flex justify-content-center">
								<div class="row col-sm-12 input-group justify-content-center">
									<input type="hidden" name="applicantId"
										value="${ certHistoryVO.certId }">
									<div class="form-group">
										<div class="input-group col-12">
											<select class="form-control" name="reason-select"
												style="width: 438px" id="reason-select">
												<option value="bad-pic">사진 불명확</option>
												<option value="wrong-info">회원정보 불일치</option>
												<option value="wrong-pic">잘못된 이미지파일</option>
												<option value="etc">기타</option>
											</select>
										</div>
									</div>
									<div class="form-group mt-2">
										<div class="input-group">
											<input type="text" id="reason-input" name="reason-input"
												style="display: none;" class="form-control"
												placeholder="거부 사유를 간략히 입력하세요." size=100>
										</div>

										<!-- 
									<div class="col-10">
										<p>거부 사유 예시)</p>
										<ul style="list-style-type:square;">
											<li>이미지 흐릿함</li>
											<li>이름 일치하지 않음</li>
											<li></li>											
										</ul>
									</div>
									 -->
									</div>
								</div>
							</div>
							<!-- /.row -->
						</div>
					</div>
					<!-- /.container -->
					<div class="modal-footer">
						<button type="button" class="btn btn-secondary"
							data-dismiss="modal">확인</button>
					</div>
				</form>
			</div>
			<!-- Footer -->
		</div>
	</div>

	<script>
		/* 승인버튼 선택시 입력란 노출 */
		$('#approval-btn').click(function() {
			$('#approval-form').show();
		});

		/* 거절 사유 '기타' 선택시 입력란 노출 */
		$('#reason-select').change(function() {
			var selected = $('#reason-select option:selected').val();
			if (selected == 'etc') {
				$('#reason-input').show();
			} else {
				$('#reason-input').hide();
			}
		});
	</script>
	<script>
	
	$("input[name=regNum]").on("change keyup paste", function(){
		if($('input[name=regNum]').val() == $('#rgd-regNum').val() ) {
			$('#label-regNum').text(' 일치');		
			$('#label-regNum').css('color','#17a2b8');
		} else {
			$('#label-regNum').text(' 일치하지 않음');		
			$('#label-regNum').css('color','#ed3c0d');			
		}
	})
	
	$("input[name=name]").on("change keyup paste", function(){
		if($('input[name=name]').val() == $('#rgd-name').val()) {
			$('#label-name').text('    일치');		
			$('#label-name').css('color','#17a2b8');
		} else {
			$('#label-name').text('    일치하지 않음');		
			$('#label-name').css('color','#ed3c0d');			
		}		
	})
	
	$("input[name=nationality]").on("change keyup paste", function(){
		if($('input[name=nationality]').val() == $('#rgd-nationality').val() ) {
			$('#label-nationality').text('    일치');		
			$('#label-nationality').css('color','#17a2b8');
		} else {
			$('#label-nationality').text('    일치하지 않음');		
			$('#label-nationality').css('color','#ed3c0d');			
		}
	})

	
	</script>



</body>
</html>