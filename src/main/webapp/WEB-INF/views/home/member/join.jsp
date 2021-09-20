<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%>
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
<jsp:include page="/WEB-INF/views/home/include/common-css.jsp" />
<jsp:include page="/WEB-INF/views/admin/include/common-css.jsp" />

</head>
<body>
	<!-- ======= Header ======= -->
	<jsp:include page="/WEB-INF/views/home/include/header.jsp" />

	<!-- ======= Main ======= -->
	<div id="wrapper">
		<!-- ---Branch searching section--- -->

		<section id="branch-search"
			class="container d-flex align-items-center justify-content-center">
			<!--
			<div
				class="container-fluid d-flex align-items-center justify-content-center">
				<div class="col-12">
					<h2 class="page-title">회원가입</h2>
					<p class="card-text">
						You can search 
					</p>
				<div class="join-section">
					<form method="post" name="form" id="form"
						onsubmit="return checkReCaptcha();"
						action="${ pageContext.request.contextPath }/join">
						<table class="table">
							<tr>
								<th>아이디</th>
								<td><input name="id" type="text" placeholder="5자 이상"
									id="id" class="w-50 float-left" required>
									<button class="btn_type2 h-50"
										style="width: 20%; margin: 10; float: right;"
										onclick="checkId()">
										<span>중복확인</span>
									</button> <span id="idCheckMsg"></span></td>
							</tr>
							<tr>
								<th>비밀번호</th>
								<td><input name="password" type="text" placeholder="비밀번호"
									class="w-50" required></td>
							</tr>
							<tr>
								<th>이름</th>
								<td><input name="name" type="text" placeholder="이름"
									class="w-50" required></td>
							</tr>
							<tr>
								<th>이메일</th>
								<td>
									<div class="birth_day w-100">
										<input name="emailId" type="text" placeholder="아이디"
											style="width: 45%" required> <span class="bar">@</span>
										<input name="emailDomain" type="text" placeholder="도메인"
											style="width: 45%" required>
									</div>
								</td>
							</tr>
							<tr>
								<th>휴대폰</th>
								<td>
									<div class="birth_day w-100">
										<input type="text" name="tel1" id="tel1" pattern="[0-9]*"
											value="" label="휴대폰번호" size="5" maxlength="3"
											placeholder="000"> <span class="bar">-</span> <input
											type="text" name="tel2" id="tel2" pattern="[0-9]*" value=""
											label="휴대폰번호" size="5" maxlength="4" placeholder="0000">
										<span class="bar">-</span> <input type="text" name="tel3"
											id="tel3" pattern="[0-9]*" value="" label="휴대폰번호" size="5"
											maxlength="4" placeholder="0000">
									</div>
								</td>
							</tr>
							<tr>
								<th>주소</th>
								<td><input name="basicAddr" type="text" placeholder="기본 주소"
									class="w-75"> <input name="post" type="text"
									placeholder="우편번호" class="w-25"><br> <input
									name="detailAddr" type="text" placeholder="상세 주소" class="w-100"></td>
							</tr>
							<tr>
								<th>성별</th>
								<td><input type="radio" name="gender" value="M"> <span>남자</span>
									<input type="radio" name="gender" value="F"> <span>여자</span>
							</tr>
							<tr>
								<th>생년월일</th>
								<td>
									<div class="birth_day w-100">
										<input type="text" name="birth_year" id="birth_year"
											pattern="[0-9]*" value="" label="생년월일" size="6" maxlength="4"
											placeholder="YYYY"> <span class="bar">/</span> <input
											type="text" name="birth[]" id="birth_month" pattern="[0-9]*"
											value="" label="생년월일" size="6" maxlength="2" placeholder="MM">
										<span class="bar">/</span> <input type="text" name="birth[]"
											id="birth_day" pattern="[0-9]*" value="" label="생년월일"
											size="6" maxlength="2" placeholder="DD">
									</div>
								</td>
							</tr>
						</table>
						<button type="submit"
							class="btn btn-primary text-white align-middle"
							style="width: 200px">
							<span>가입하기</span>
						</button>
					</form>
				</div>
			</div>
			</div>		
		-->

			<div
				class="container-fluid d-flex align-items-center justify-content-center">
				<div class="col-12">
					<h2 class="page-title">
						<spring:message code="member.join"></spring:message>
					</h2>
					<p class="card-text">Welcome to HanaEZ UP</p>
					<div class="row align-items-center justify-content-center">
						<div class="col-md-12 align-items-center">
							<div class="card shadow">
								<div class="card-body">
									<div class="container">
										<div class="row">
											<div class="col-md-12">
												<!-- begin panel -->
												<div class="panel panel-inverse p-3"
													data-sortable-id="form-validation-2">
													<h4 class="panel-title">Very EZ! 본인인증 없이 EZMember로 간편
														회원가입</h4>
												</div>
												<div class="panel-body panel-form col-md-12">
													<form class="form-horizontal form-bordered" method="post"
														action="${ pageContext.request.contextPath }/join"
														data-parsley-validate="true">
														<div class="form-group">
															<label class="control-label col-md-4 col-sm-4">아이디*
																:</label>
															<div class="col-md-6 ">
																<input class="form-control" type="text" id="alphanum"
																	name="alphanum" data-type="alphanum" placeholder="id"
																	data-parsley-required="true" />
															</div>
															<div class="col-md-6">
																<input type="button" onclick="javascript:idCheck()"
																	value="중복체크" class="btn btn-outline-primary w-25">
																<br>
																<div id="idCheckMsg"></div>
															</div>
														</div>
														<div class="form-group">
															<label class="control-label col-md-4 col-sm-4">비밀번호*
																:</label>
															<div class="col-md-6 col-sm-6">
																<input class="form-control" type="password"
																	name="password" data-type="alphanum"
																	placeholder="password" data-parsley-required="true" />

															</div>
															<div class="col-md-6">
																<p class="mb-2">Password requirements</p>
																<p class="small text-muted mb-2">To create a new
																	password, you have to meet all of the following
																	requirements:</p>
																<ul class="small text-muted pl-4 mb-0">
																	<li>Minimum 8 character</li>
																	<li>At least one special character</li>
																	<li>At least one number</li>
																	<li>Can’t be the same as a previous password</li>
																</ul>
															</div>
														</div>
														<div class="form-group">
															<label class="control-label col-md-4 col-sm-4">이름*
																:</label>
															<div class="col-md-6 col-sm-6">
																<input class="form-control" type="text" name="name"
																	data-type="alphanum" placeholder="name"
																	data-parsley-required="true" />
															</div>
														</div>
														<div class="form-group">
															<label class="control-label col-md-4 col-sm-4">생년월일*
																:</label>
															<div class="col-md-6 col-sm-6">
																<input class="form-control" type="text"
																	id="data-dateIso" name="birthday"
																	data-parsley-pattern="#[A-Fa-f0-9]{6}"
																	placeholder="YYYY-MM-DD" data-parsley-required="true" />
															</div>
														</div>
														<div class="form-group">
															<label class="control-label col-md-4 col-sm-4">국적*
																:</label>
															<div class="col-md-6 col-sm-6">
																<select class="form-control" id="select-required"
																	name="nationality" data-parsley-required="true">
																	<option value="">Choose nationality</option>
																	<option value="ko">한국 / Korea, Republic of</option>
																	<option value="us">미국 / United States</option>
																	<option value="th">태국 / Thailand</option>
																	<option value="ch">중국 / China</option>
																</select>
															</div>
														</div>
														<div class="form-group">
															<label class="control-label col-md-4 col-sm-4">국적구분
																:</label>
															<div class="col-md-6 col-sm-6">
																<div class="">
																	<label><input type="checkbox" name="fruits"
																		value="내국인">내국인</label> <label><input
																		type="checkbox" name="fruits" value="외국인">외국인</label>
																</div>
															</div>
														</div>
														<!-- 
														<div class="form-group">
															<div class="col-md-6 col-sm-6">
																<div class="checkbox">
																	<label><input type="checkbox" id="mincheck"
																		name="mincheck[]" data-parsley-mincheck="2" value="foo"
																		required /> Checkbox 1</label>
																</div>
																<div class="checkbox">
																	<label><input type="checkbox" name="mincheck[]"
																		value="bar" /> Checkbox 2</label>
																</div>
																<div class="checkbox">
																	<label><input type="checkbox" name="mincheck[]"
																		value="baz" /> Checkbox 3</label>
																</div>
															</div>
														</div>
														 -->
														<div class="form-group">
															<label class="control-label col-md-4 col-sm-4">주소
																:</label>
															<div class="col-md-6 col-sm-6">
																<input class="form-control" type="text" name="address"
																	placeholder="" data-required="true" />
															</div>
														</div>
														<div class="form-group">
															<label class="control-label col-md-4 col-sm-4"></label>
															<div class="col-md-6 col-sm-6">
																<button type="submit" class="btn btn-primary">회원가입</button>
															</div>
														</div>
													</form>
												</div>
											</div>
										</div>
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</section>
		<!-- end panel -->
		<!-- End Join Section -->

		<!-- ======= Footer ======= -->
		<jsp:include page="/WEB-INF/views/admin/include/common-js.jsp" />
		<jsp:include page="/WEB-INF/views/home/include/common-js.jsp" />
		<!-- End Footer -->
	</div>


	<script>
		function checkId() {
			let id = $('#id').val();
			$('#idCheckMsg').css("font-size", "11px");

			if (id.length == 0)
				$('#idCheckMsg').html("");
			else if (id.length < 5) {
				$('#idCheckMsg').html("5자이상 입력하세요");
				$('#idCheckMsg').css("color", "red")
			} else {
				$.ajax({
					url : "${ pageContext.request.contextPath }/idCheck",
					type : "post",
					data : {
						"id" : id
					},
					success : function(result) {
						if (result.trim("") == 'true') {
							$('#idCheckMsg').html("사용 가능한 아이디입니다.");
							$('#idCheckMsg').css("color", "green");
						} else {
							$('#idCheckMsg').html("이미 사용중인 아이디입니다.");
							$('#idCheckMsg').css("color", "red");
						}
					},
					error : function() {
						alert('error');
					}
				})
			}
		}
	</script>

</body>
</html>