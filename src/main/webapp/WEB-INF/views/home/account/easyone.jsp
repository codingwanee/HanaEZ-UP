<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
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
	<!-- ======= LOGIN SECTION ======= -->
	<div id="wrapper">
		<!-- ---Branch searching section--- -->
		<section id="login" class="container"
			class="container d-flex align-items-center justify-content-center">
			<div
				class="container-fluid align-items-center justify-content-center">
				<div class="col-sm-12">
					<h2 class="page-title">
						<spring:message code="easyone.title"></spring:message>
					</h2>
					<p class="card-text">
						<spring:message code="easyone.text"></spring:message>
					</p>
					<div class="row mb-4">
						<div class="col-md-12">
							<div class="card shadow">
								<div class="card-body">
									<div
										class="col-lg-12 d-flex align-items-center justify-content-center p-5">

										<div id="HANA_CONTENTS_DIV">
											<h4>Easy-One Pack Account</h4>

											<div class="info01 pb0">
												<ul>
													<li><span class="color02">A money market
															deposit account (MMDA)</span> especially for foreign customers
														that offers <span class="color02">electronic
															banking and ATM fee exemptions</span> for those <br>using a
														check card or salary transfer service.</li>
												</ul>
												<ul class="division">
													<li><strong>Real-Name Foreigner or Foreign
															Business Operator : </strong>Real-Name Foreigner Personal Account</li>
													<li><strong>Enrollment Amount : </strong>No
														restriction</li>
													<li class="txt_align"><strong class="al_span_tit">Applied
															Interest Rate (Pre-tax, at maturity) : </strong>
														<ul class="al_span">
															<li>Interest rates posted on the KEB Hana Bank
																website or at a branch on the date of account opening or
																renewal.</li>
															<li>2013. 3. 25 Current Applied Interest Rate
																<ul>
																	<li class="bg_none pl0">For average balance of
																		less than KRW 50,000,000: 0.1% per annum</li>
																	<li class="bg_none pl0">For average balance of KRW
																		50,000,000 or more: 0.2% per annum</li>
																</ul>
															</li>
														</ul></li>
												</ul>
											</div>

											<h5 class="mt26 mt-5">Preferential Services</h5>
											<ul class="liType1">
												<li>The following preferential services will be
													provided to a customer with this account type if the
													respective conditions are met.</li>
												<li class="mt5"><strong>Preferential Service 1</strong>
													<ul class="liType2">
														<li>Criteria: History of using this account as the
															payment account for a Rainbow check card, Global check
															card, or KEB Hana credit card. <span class="color02">-
																Note</span>
														</li>
														<li>Service Information (Subject to transactions
															conducted via this account)
															<ul class="liType3">
																<li>Other electronic banking transfer fees waived.
																	<span class="color02">- Note 1</span>
																</li>
																<li><span class="color03">Fees waived for
																		transfers to a KEB Hana Bank account or withdrawals
																		made after business hours using a KEB Hana Bank ATM.
																		(Not applicable for transfers to 3rd-party banks.)</span></li>
															</ul>
														</li>
														<li>Method of Provision: Preferential service
															provided the following month if “conditions are satisfied
															in the previous month.”</li>
													</ul>
													<ul>
														<li class="pl0 bg_none color02">Note: N°N Card, 2X
															Card, Crossmile Card, Signature Card, Global Card, and
															Expat Card</li>
														<li class="pl0 color02 bg_none">Note 1: Internet,
															Phone, Mobile, and Smartphone Banking.</li>
													</ul></li>
												<li class="mt5"><strong>Preferential Service 2</strong>
													<ul class="liType2">
														<li>Criteria: If salary is paid to this account or at
															least KRW 300,000 was deposited into an Easy-One Pack
															Deposit account the previous month (in the customer's
															name.) <span class="color02">- Note 2</span>
														</li>
														<li>Service Information (Subject to transactions
															conducted via this account)
															<ul class="liType3">
																<li><span class="color03">Fee exemptions
																		provided in Preferential Service 1.</span></li>
																<li><span class="color03">Withdrawal fee
																		waived when using a 3rd-party ATM to withdraw funds
																		from a KEB Hana Bank account.</span><br class="break">
																	(Limited to on- and off-site ATMs operated by KEB Hana
																	Bank.)</li>
															</ul>
														</li>
														<li>Method of Provision: Preferential service shall
															be provided in the following month if “a deposit was made
															the previous two months” or "KRW 300,000 or more was
															deposited into an Easy-One Pack Deposit Account.”</li>
													</ul>
													<ul>
														<li class="pl0 bg_none color02">Note 2: If recognized
															as salary.
															<ul>
																<li class="bg_none color02">Deposits via branch
																	counter, Internet, bulk Giro transfer, bulk CMS
																	transfer, 3rd-party bank exchange, and electronic
																	banking network.
																	<ul>
																		<li class="color02 bg_none">
																			<ul class="liType3">
																				<li class="ml-10 color02">If the deposit (code)
																					is a salary (pension) type fund.</li>
																				<li class="ml-10 color02">Transactions that are
																					salary, wage, pay, payroll, bonus, pension, etc.</li>
																				<li class="ml-10 color02">If depositing on a
																					designated salary transfer date.</li>
																				<li class="ml-10 color02">If KRW 500,000 or
																					more is deposited within two business days of the
																					salary date specified by the customer.</li>
																			</ul>
																		</li>
																	</ul>
																</li>
															</ul>
														</li>
													</ul></li>
											</ul>
											<h5 class="mt30">Special Preferential Service</h5>
											<ul class="liType1">
												<li>Preferential Services 1 and 2 are provided until
													the end of the following business day from the date of
													initial sign-up regardless of the criteria.</li>
											</ul>

											<h5 class="mt30">Terminate Contract</h5>
											<ul class="liType1">
												<li>Termination can be made at a branch.</li>
											</ul>

											<div class="info01 mt-5">
												<h5>Guide</h5>
												<ul>
													<li>This deposit account is protected by the Korea
														Deposit Insurance Corp. in accordance with the Depositor
														Protection Act, and the protection limit is a maximum of
														KRW 50,000,000 per person,<br> including all
														principal and fixed interest for eligible financial
														products at KEB Hana Bank. The amount in excess of KRW
														50,000,000 is not protected.
													</li>
													<li>Terms of preferential service are subject to
														change depending on bank conditions. Any changes to
														relevant information (including reasons for change) <br>shall
														be announced on the KEB Hana Bank website and at branches
														for one month.
													</li>
													<li>This information represents a summary of the
														contents. For details, please refer to the KEB Hana Bank
														Terms &amp; Conditions or individual agreements.<br>
														We recommend seeking the advice of a specialist if
														necessary.
													</li>
												</ul>
											</div>
											<div
												class="m-3 row col-sm-12 justify-content-center align-items-center">
												<br>
												<br>
												<a href="${ pageContext.request.contextPath }/account/open">
													<button class="mt-3 btn btn-primary">개설하러 가기</button>
												</a>
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
	</div>


</body>
</html>