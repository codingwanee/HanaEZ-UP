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

<style>
.info01 {
	border: 1px solid #f2f6f7;
}

.tbl_tbldiv th {
	background-color: #f2f6f7;
}

.cell-top th, .cell-top td{
	border-top: 2px solid #bcbcbc;
}

.cell-bottom td,  .cell-bottom th{
	border-bottom: 2px solid #bcbcbc;
}
</style>

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
						<h2 class="page-title">
							Global Check Card
						</h2>
						<p class="card-text mb-5">
							
						</p>
						<div class="pop_ty01 col-10" tabindex="0">
							<h4>Global Check (Visa or Local) Information Details</h4>
							
							<div class=" pop_cont">
								<div class="row mt-5 mb-5">
									<div class="col-sm-6">
										<img
											src="${ pageContext.request.contextPath }/resources/assets/img/illusts/hanacard.png"
											class="img-fluid animated" alt="main-fluid-img"
											style="width: 100%">
									</div>
									<div class="info01 pop_card_info mt25 col-sm-6">
										<ul class="">
											<li><strong>Eligible Customers</strong>: Foreign Residents<br></li>
											<li class=""><strong>Base Product</strong>: Power
												Check Card-based<br></li>
											<li class=""><strong>Annual Fee and Other
													Issuance Fees</strong>: No</li>
										</ul>
									</div>
								</div>
								<h5>Products and Services</h5>
								<div class="tbl_tbldiv">
									<table class="table"
										summary="The table includes rewards, transportation/gas, overseas card use, health/food and beverage, movie and entertainment event, and language support service.">
										
										<colgroup>
											<col style="width: 22%">
											<col style="width: 78%">
										</colgroup>
										<tbody>
											<tr class="cell-top">
												<th class="b-tnone" scope="row">Reward</th>
												<td class="b-tnone tbl_left">
													<ul class="liType2">
														<li>Accumulate Yes Point (0.5%)</li>
													</ul>
												</td>
											</tr>
											<tr>
												<th scope="row">Transportation/Gas</th>
												<td class="tbl_left">
													<ul class="liType2">
														<li>50 Yes Points given for every liter filled up at
															Hyundai Oilbank</li>
														<li>Postpaid or Prepaid (Seoul T-Money)
															Transportation Card</li>
													</ul>
												</td>
											</tr>
											<tr>
												<th scope="row">Use Overseas</th>
												<td class="tbl_left">
													<ul class="liType2">
														<li>Visa card available only (local cards not
															accepted)</li>
													</ul>
												</td>
											</tr>
											<tr>
												<th scope="row">Health/Food and Beverage</th>
												<td class="tbl_left">
													<ul class="liType2">
														<li>Up to 10-25% off at TGI Friday’s</li>
													</ul>
												</td>
											</tr>
											<tr>
												<th scope="row">Movies and Entertainment Events</th>
												<td class="tbl_left">
													<ul class="liType2">
														<li>Up to KRW 4,000 off on online bookings
															(Interpark, Ticketlink)</li>
													</ul>
												</td>
											</tr>
											<tr>
												<th scope="row">Air Ticket and Travel</th>
												<td class="tbl_left">
													<ul class="liType2">
														<li>Air Ticket: up to 5% off on international flights</li>
														<li>3-5% off on domestic or overseas travel packages</li>
														<li>Up to 5% off on overseas hotel bookings</li>
														<li>Global Check (Visa or Local) Information Details</li>
													</ul>
												</td>
											</tr>
											<tr class="cell-bottom">
												<th scope="row">Language Support Service</th>
												<td class="tbl_left">
													<ul class="liType2">
														<li>24-hour Customer Support Center (English service
															available)</li>
														<li>Manage English Website</li>
														<li>Send English User Guide</li>
														<li>English text message will be sent on your card
															use.</li>
													</ul>
												</td>
											</tr>
										</tbody>
									</table>
								</div>

								<div class="info01 mt50">
									<h5>Guide</h5>
									<ul>
										<li>The information above is a summary of the service.
											For details, visit KEB Hana Bank website (<a
											href="http://www.hanabank.com" target="_blank"
											title="New window Opens.">www.hanabank.com</a>).
										</li>
										<li>The card service above will be maintained throughout
											the year and beyond from its release, and we will notify you
											of any change six months prior to that.<br> In case of
											an unavoidable accident such as shutdown or insolvency of an
											affiliated company, however, we will try to pre-notify you of
											any change,<br> otherwise we will notify you afterwards.
										</li>
										<li>Having more credit cards than you need may affect
											your credit rating or spending limit.</li>
										<li>Overdue interest rate of 23.0 - 29.0% will apply
											according to your interest rate for cash advance and overdue
											period (as of January 2013).</li>
										<li>Spending too much with credit cards may threaten your
											household finance.</li>
									</ul>
								</div>

							</div>
<!-- 							<div class="pop_close">
								<a href="#//HanaBank" onclick="javascript:window.close();"><img
									src="https://image.kebhana.com/pbk/easyone/resource/img/contents/btn_popclose.gif"
									alt="Close Pop-up"></a>
							</div> -->
						</div>
					</div>
				</div>
			</div>
		</section>
	</div>

</body>
</html>