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

<!-- Favicons -->
<link
	href="${ pageContext.request.contextPath }/resources/assets/img/favicon.png"
	rel="icon">

<!-- Google Fonts -->
<link
	href="https://fonts.googleapis.com/css?family=Open+Sans:300,300i,400,400i,600,600i,700,700i|Raleway:300,300i,400,400i,600,600i,700,700i"
	rel="stylesheet">

<jsp:include page="/WEB-INF/views/home/include/common-css.jsp" />
<jsp:include page="/WEB-INF/views/admin/include/common-css.jsp" />

<link href="http://www.jqueryscript.net/css/jquerysctipttop.css"
	rel="stylesheet" type="text/css">
<link
	href="${ pageContext.request.contextPath }/resources/css/jquery-nicelabel.css"
	rel="stylesheet">

</head>
<body>

	<!-- ======= Header ======= -->
	<jsp:include page="/WEB-INF/views/home/include/header.jsp" />



	<!-- ======= Main ======= -->
	<div id="wrapper">
		<!-- ---Branch searching section--- -->
		<section id="branch-search"
			class="container d-flex align-items-center justify-content-center">
			<div
				class="container-fluid d-flex align-items-center justify-content-center">
				<div class="col-12">
					<h2 class="page-title">
						Easy One Foreigner Service
					</h2>
					<p class="card-text mb-5">
					</p>

					<div class="info01">
						<p class="etcTitle color03 mt0">KEB Hana Bank's special
							service for foreigners living in Korea!</p>
						<ul class="lst_01">
							<li><span class="color03">This is a one-stop service
									that provides useful products and services suitable for foreign
									customers in Korean, English, Chinese, Japanese, and
									Vietnamese.</span></li>
							<li>The Easy-One foreigner service provides services
								especially for expatriates, foreign workers, <br>and
								international students in Korea. For a more convenient user
								experience, online banking transactions are structured by
								frequency of use.
							</li>
							<li>Personal banking customers who signed up for KEB Hana
								Bank's online banking may continue to use the services through
								the Easy-One foreigner service.</li>
						</ul>
					</div>

					<h5 class="mt8 mt-5 mb-3"">Provides Useful Information</h5>
					<div class="col-10">
						<table class="table"
							summary="This is a Provides Useful Information table consisting of Foreign Worker,Expatriate,International Student,Non-Financial Services,BEST PRODUCT.">
							<colgroup>
								<col style="width: 20%;">
								<col style="width: 80%;">
							</colgroup>
							<tbody>
								<tr class="cell-top">
									<th class="b-tnone tbl_left" scope="row">Foreign Worker</th>
									<td class="b-tnone tbl_left">Required immigration-related
										information; various types of insurance and benefits; Korea
										Support Center for Foreign Workers and other related
										organizations and foreigner support groups.</td>
								</tr>
								<tr>
									<th class="tbl_left" scope="row">Expatriate</th>
									<td class="tbl_left">Financial services as well as
										newsletters and information on various products and services
										required for a productive life in Korea <br>for KEB Hana
										Bank’s expatriate customers.
									</td>
								</tr>
								<tr>
									<th class="tbl_left" scope="row">International Student</th>
									<td class="tbl_left">International Student Identification
										Card check card, benefits for Chinese international students,
										and the Happy Email service.</td>
								</tr>
								<tr>
									<th class="tbl_left" scope="row">Non-Financial Services</th>
									<td class="tbl_left">Relocation services, cultural and
										leisure information.</td>
								</tr>
								<tr class="cell-bottom">
									<th class="" scope="row">BEST PRODUCT</th>
									<td class="">Deposit account, overseas remittance,
										and card information guides for foreign customers.</td>
								</tr>
							</tbody>
						</table>
					</div>

					<h5 class="mt-5 mb-3">Internet Banking Transaction</h5>
					<div class="tbldiv">
						<table class="table"
							summary="This is a Internet Banking Transaction table consisting of Account Inquiry,Domestic Transfer,Overseas Remittance,Giro,Simple Inquiry,Digital Certificate Center,Security Center,Report Incident.">
							<colgroup>
								<col style="width: 20%;">
								<col style="width: 80%;">
							</colgroup>
							<tbody>
								<tr class="cell-top">
									<th class="b-tnone tbl_left" scope="row">Account Inquiry</th>
									<td class="b-tnone tbl_left">Account status and
										transaction history inquiries.</td>
								</tr>
								<tr>
									<th class="tbl_left" scope="row">Domestic Transfer</th>
									<td class="tbl_left">KRW transfer, foreign currency
										transfer, recurring transfer, and transfer results inquiry.</td>
								</tr>
								<tr>
									<th class="tbl_left" scope="row">Overseas Remittance</th>
									<td class="tbl_left">Remittance information registration,
										remittance request, and remittance results inquiry.</td>
								</tr>
								<tr>
									<th class="tbl_left" scope="row">Giro</th>
									<td class="tbl_left">Payment, payment voucher, and payment
										receipt record.</td>
								</tr>
								<tr>
									<th class="tbl_left" scope="row">Simple Inquiry</th>
									<td class="tbl_left">Balance and transaction history
										inquiries.</td>
								</tr>
								<tr>
									<th class="tbl_left" scope="row">Digital Certificate
										Center</th>
									<td class="tbl_left">Issue/reissue digital certificate,
										revoke digital certificate, register/revoke 3rd-party
										bank/issuer digital certificate, manage digital certificate,
										renew digital certificate, import/export from/to smart device.</td>
								</tr>
								<tr>
									<th class="tbl_left" scope="row">Security Center</th>
									<td class="tbl_left">Precautions, security measures, and
										security clinic.</td>
								</tr>
								<tr  class="cell-bottom">
									<th class="tbl_left" scope="row">Report Incident</th>
									<td class="tbl_left">Cash/debit card and passbook (seal)
										loss report. Cashier's check loss reporting guide and
										OTP/security card loss reporting guide.</td>
								</tr>
							</tbody>
						</table>
					</div>
				</div>
			</div>
		</section>
	</div>
	<!-- ======= Footer ======= -->
	<%@include file="/WEB-INF/views/home/include/footer.jsp"%>
	<jsp:include page="/WEB-INF/views/admin/include/common-js.jsp" />
	<jsp:include page="/WEB-INF/views/home/include/common-js.jsp" />
	<!-- End Footer -->

</body>
</html>