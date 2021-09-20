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

<style>
th{
	background-color: #f2f6f7;
}
th, td {
	border: 1px solid #dadcdb;
}
.cell-top th{
	border-top: 2px solid #bcbcbc;
}

.cell-bottom td {
	border-bottom: 2px solid #bcbcbc;
}
</style>

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
				<h2 class="page-title">환율정보</h2>
						<p class="card-text">
						2020/09/30 23:57:31 기준으로 조회된 환율입니다.
						</p>
					<div class="col-sm-10">
						<table class="table"
							summary="This is a Current Exchange Rate Inquiry History table consisting of Currency,Cash,Wire Transfer,T/C Buy Rate,Foreign CurrencyCheckSell Rate,Basic Rate ofExchange,Exchange Commission Rate,USDExchange Rate,Buy Rate,Sell Rate,When Sending,When Receiving,Exchange Rate,Spread,Exchange Rate,Spread.">
							<caption>Current Exchange Rate Inquiry History</caption>
							<colgroup>
								<col style="width: 8%">
								<col style="width: 7%">
								<col style="width: 7%">
								<col style="width: 7%">
								<col style="width: 7%">
								<col style="width: 7%">
								<col style="width: 8%">
								<col style="width: 9%">
								<col style="width: 8%">
								<col style="width: 8%">
								<col style="width: 8%">
								<col style="width: 8%">
								<col style="width: *">
							</colgroup>
							<thead>
								<tr class="cell-top">
									<th class="b-tnone" scope="col" rowspan="3">Currency</th>
									<th class="b-tnone" scope="col" colspan="4">Cash</th>
									<th class="b-tnone" scope="col" colspan="2">Wire Transfer</th>
									<th class="b-tnone" scope="col" rowspan="3">T/C Buy Rate</th>
									<th class="b-tnone" scope="col" rowspan="3">Foreign
										Currency<br>Check<br>Sell Rate
									</th>
									<th class="b-tnone" scope="col" rowspan="3">Basic Rate of<br>Exchange
									</th>
									<th class="b-tnone" scope="col" rowspan="3">Exchange
										Commission Rate</th>
									<th class="b-tnone" scope="col" rowspan="3">USD<br>Exchange
										Rate
									</th>
								</tr>
								<tr>
									<th scope="col" colspan="2">Buy Rate</th>
									<th scope="col" colspan="2">Sell Rate</th>
									<th scope="col" rowspan="2">When Sending</th>
									<th scope="col" rowspan="2">When Receiving</th>
								</tr>
								<tr>
									<th scope="col">Exchange Rate</th>
									<th scope="col">Spread</th>
									<th scope="col">Exchange Rate</th>
									<th scope="col">Spread</th>
								</tr>
							</thead>
							<tbody>


								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('USD','20200930');">
											 USD 
									</a></td>
									<td class="tbl_right f12_ar">1,189.45</td>
									<td class="tbl_right f12_ar">1.75</td>
									<td class="tbl_right f12_ar">1,148.55</td>
									<td class="tbl_right f12_ar">1.75</td>
									<td class="tbl_right f12_ar">1,180.40</td>
									<td class="tbl_right f12_ar">1,157.60</td>
									<td class="tbl_right f12_ar">1,183.02</td>
									<td class="tbl_right f12_ar">1,156.96</td>
									<td class="tbl_right f12_ar">1,169.00</td>
									<td class="tbl_right f12_ar">1.9966</td>
									<td class="tbl_right f12_ar">1.0000</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('JPY','20200930');">
											 JPY (100) 
									</a></td>
									<td class="tbl_right f12_ar">1,126.43</td>
									<td class="tbl_right f12_ar">1.75</td>
									<td class="tbl_right f12_ar">1,087.69</td>
									<td class="tbl_right f12_ar">1.75</td>
									<td class="tbl_right f12_ar">1,117.90</td>
									<td class="tbl_right f12_ar">1,096.22</td>
									<td class="tbl_right f12_ar">1,118.13</td>
									<td class="tbl_right f12_ar">1,095.70</td>
									<td class="tbl_right f12_ar">1,107.06</td>
									<td class="tbl_right f12_ar">1.8865</td>
									<td class="tbl_right f12_ar">0.9470</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('EUR','20200930');">
											 EUR 
									</a></td>
									<td class="tbl_right f12_ar">1,394.29</td>
									<td class="tbl_right f12_ar">1.99</td>
									<td class="tbl_right f12_ar">1,339.89</td>
									<td class="tbl_right f12_ar">1.99</td>
									<td class="tbl_right f12_ar">1,380.76</td>
									<td class="tbl_right f12_ar">1,353.42</td>
									<td class="tbl_right f12_ar">1,387.59</td>
									<td class="tbl_right f12_ar">1,352.89</td>
									<td class="tbl_right f12_ar">1,367.09</td>
									<td class="tbl_right f12_ar">1.4081</td>
									<td class="tbl_right f12_ar">1.1695</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('CNY','20200930');">
											 CNY 
									</a></td>
									<td class="tbl_right f12_ar">179.86</td>
									<td class="tbl_right f12_ar">5.00</td>
									<td class="tbl_right f12_ar">162.74</td>
									<td class="tbl_right f12_ar">5.00</td>
									<td class="tbl_right f12_ar">173.01</td>
									<td class="tbl_right f12_ar">169.59</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">171.30</td>
									<td class="tbl_right f12_ar">5.3616</td>
									<td class="tbl_right f12_ar">0.1465</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('HKD','20200930');">
											 HKD 
									</a></td>
									<td class="tbl_right f12_ar">153.81</td>
									<td class="tbl_right f12_ar">1.97</td>
									<td class="tbl_right f12_ar">147.87</td>
									<td class="tbl_right f12_ar">1.97</td>
									<td class="tbl_right f12_ar">152.34</td>
									<td class="tbl_right f12_ar">149.34</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">149.25</td>
									<td class="tbl_right f12_ar">150.84</td>
									<td class="tbl_right f12_ar">2.5550</td>
									<td class="tbl_right f12_ar">0.1290</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('THB','20200930');">
											 THB 
									</a></td>
									<td class="tbl_right f12_ar">38.83</td>
									<td class="tbl_right f12_ar">5.00</td>
									<td class="tbl_right f12_ar">34.78</td>
									<td class="tbl_right f12_ar">6.00</td>
									<td class="tbl_right f12_ar">37.35</td>
									<td class="tbl_right f12_ar">36.63</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">36.61</td>
									<td class="tbl_right f12_ar">36.99</td>
									<td class="tbl_right f12_ar">2.5250</td>
									<td class="tbl_right f12_ar">0.0316</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('TWD','20200930');">
											 TWD 
									</a></td>
									<td class="tbl_right f12_ar">45.54</td>
									<td class="tbl_right f12_ar">13.10</td>
									<td class="tbl_right f12_ar">37.46</td>
									<td class="tbl_right f12_ar">7.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">40.27</td>
									<td class="tbl_right f12_ar">2.3950</td>
									<td class="tbl_right f12_ar">0.0344</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('PHP','20200930');">
											 PHP 
									</a></td>
									<td class="tbl_right f12_ar">26.53</td>
									<td class="tbl_right f12_ar">10.00</td>
									<td class="tbl_right f12_ar">22.15</td>
									<td class="tbl_right f12_ar">8.20</td>
									<td class="tbl_right f12_ar">24.36</td>
									<td class="tbl_right f12_ar">23.88</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">24.12</td>
									<td class="tbl_right f12_ar">3.6740</td>
									<td class="tbl_right f12_ar">0.0206</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('SGD','20200930');">
											 SGD 
									</a></td>
									<td class="tbl_right f12_ar">870.73</td>
									<td class="tbl_right f12_ar">1.99</td>
									<td class="tbl_right f12_ar">836.77</td>
									<td class="tbl_right f12_ar">1.99</td>
									<td class="tbl_right f12_ar">862.28</td>
									<td class="tbl_right f12_ar">845.22</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">844.71</td>
									<td class="tbl_right f12_ar">853.75</td>
									<td class="tbl_right f12_ar">2.4250</td>
									<td class="tbl_right f12_ar">0.7303</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('AUD','20200930');">
											 AUD 
									</a></td>
									<td class="tbl_right f12_ar">848.54</td>
									<td class="tbl_right f12_ar">1.97</td>
									<td class="tbl_right f12_ar">815.76</td>
									<td class="tbl_right f12_ar">1.97</td>
									<td class="tbl_right f12_ar">840.47</td>
									<td class="tbl_right f12_ar">823.83</td>
									<td class="tbl_right f12_ar">844.63</td>
									<td class="tbl_right f12_ar">823.32</td>
									<td class="tbl_right f12_ar">832.15</td>
									<td class="tbl_right f12_ar">2.2750</td>
									<td class="tbl_right f12_ar">0.7118</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('VND','20200930');">
											 VND (100) 
									</a></td>
									<td class="tbl_right f12_ar">5.63</td>
									<td class="tbl_right f12_ar">11.80</td>
									<td class="tbl_right f12_ar">4.45</td>
									<td class="tbl_right f12_ar">11.80</td>
									<td class="tbl_right f12_ar">5.09</td>
									<td class="tbl_right f12_ar">4.99</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">5.04</td>
									<td class="tbl_right f12_ar">2.4250</td>
									<td class="tbl_right f12_ar">0.0043</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('GBP','20200930');">
											 GBP 
									</a></td>
									<td class="tbl_right f12_ar">1,533.42</td>
									<td class="tbl_right f12_ar">1.97</td>
									<td class="tbl_right f12_ar">1,474.18</td>
									<td class="tbl_right f12_ar">1.97</td>
									<td class="tbl_right f12_ar">1,518.83</td>
									<td class="tbl_right f12_ar">1,488.77</td>
									<td class="tbl_right f12_ar">1,526.35</td>
									<td class="tbl_right f12_ar">1,487.94</td>
									<td class="tbl_right f12_ar">1,503.80</td>
									<td class="tbl_right f12_ar">2.0208</td>
									<td class="tbl_right f12_ar">1.2864</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('CAD','20200930');">
											 CAD 
									</a></td>
									<td class="tbl_right f12_ar">892.23</td>
									<td class="tbl_right f12_ar">1.97</td>
									<td class="tbl_right f12_ar">857.77</td>
									<td class="tbl_right f12_ar">1.97</td>
									<td class="tbl_right f12_ar">883.75</td>
									<td class="tbl_right f12_ar">866.25</td>
									<td class="tbl_right f12_ar">888.12</td>
									<td class="tbl_right f12_ar">865.72</td>
									<td class="tbl_right f12_ar">875.00</td>
									<td class="tbl_right f12_ar">2.2050</td>
									<td class="tbl_right f12_ar">0.7485</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('MYR','20200930');">
											 MYR 
									</a></td>
									<td class="tbl_right f12_ar">298.89</td>
									<td class="tbl_right f12_ar">6.30</td>
									<td class="tbl_right f12_ar">260.38</td>
									<td class="tbl_right f12_ar">7.40</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">278.37</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">281.18</td>
									<td class="tbl_right f12_ar">3.8650</td>
									<td class="tbl_right f12_ar">0.2405</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('RUB','20200930');">
											 RUB 
									</a></td>
									<td class="tbl_right f12_ar">15.84</td>
									<td class="tbl_right f12_ar">7.00</td>
									<td class="tbl_right f12_ar">13.19</td>
									<td class="tbl_right f12_ar">11.00</td>
									<td class="tbl_right f12_ar">14.95</td>
									<td class="tbl_right f12_ar">14.67</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">14.81</td>
									<td class="tbl_right f12_ar">6.4750</td>
									<td class="tbl_right f12_ar">0.0127</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('ZAR','20200930');">
											 ZAR 
									</a></td>
									<td class="tbl_right f12_ar">72.68</td>
									<td class="tbl_right f12_ar">6.00</td>
									<td class="tbl_right f12_ar">63.09</td>
									<td class="tbl_right f12_ar">8.00</td>
									<td class="tbl_right f12_ar">69.39</td>
									<td class="tbl_right f12_ar">67.75</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">68.57</td>
									<td class="tbl_right f12_ar">6.7250</td>
									<td class="tbl_right f12_ar">0.0587</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('NOK','20200930');">
											 NOK 
									</a></td>
									<td class="tbl_right f12_ar">126.64</td>
									<td class="tbl_right f12_ar">2.45</td>
									<td class="tbl_right f12_ar">120.60</td>
									<td class="tbl_right f12_ar">2.45</td>
									<td class="tbl_right f12_ar">124.85</td>
									<td class="tbl_right f12_ar">122.39</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">122.32</td>
									<td class="tbl_right f12_ar">123.62</td>
									<td class="tbl_right f12_ar">2.1950</td>
									<td class="tbl_right f12_ar">0.1057</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('NZD','20200930');">
											 NZD 
									</a></td>
									<td class="tbl_right f12_ar">785.18</td>
									<td class="tbl_right f12_ar">1.97</td>
									<td class="tbl_right f12_ar">754.86</td>
									<td class="tbl_right f12_ar">1.97</td>
									<td class="tbl_right f12_ar">777.72</td>
									<td class="tbl_right f12_ar">762.32</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">761.79</td>
									<td class="tbl_right f12_ar">770.02</td>
									<td class="tbl_right f12_ar">2.5250</td>
									<td class="tbl_right f12_ar">0.6587</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('DKK','20200930');">
											 DKK 
									</a></td>
									<td class="tbl_right f12_ar">188.18</td>
									<td class="tbl_right f12_ar">2.45</td>
									<td class="tbl_right f12_ar">179.18</td>
									<td class="tbl_right f12_ar">2.45</td>
									<td class="tbl_right f12_ar">185.51</td>
									<td class="tbl_right f12_ar">181.85</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">181.77</td>
									<td class="tbl_right f12_ar">183.68</td>
									<td class="tbl_right f12_ar">1.5850</td>
									<td class="tbl_right f12_ar">0.1571</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('MXN','20200930');">
											 MXN 
									</a></td>
									<td class="tbl_right f12_ar">57.75</td>
									<td class="tbl_right f12_ar">10.00</td>
									<td class="tbl_right f12_ar">48.09</td>
									<td class="tbl_right f12_ar">8.40</td>
									<td class="tbl_right f12_ar">53.02</td>
									<td class="tbl_right f12_ar">51.98</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">52.50</td>
									<td class="tbl_right f12_ar">6.5580</td>
									<td class="tbl_right f12_ar">0.0449</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('MNT','20200930');">
											 MNT 
									</a></td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.41</td>
									<td class="tbl_right f12_ar">14.9750</td>
									<td class="tbl_right f12_ar">0.0004</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('BHD','20200930');">
											 BHD 
									</a></td>
									<td class="tbl_right f12_ar">3,297.93</td>
									<td class="tbl_right f12_ar">6.40</td>
									<td class="tbl_right f12_ar">2,851.60</td>
									<td class="tbl_right f12_ar">8.00</td>
									<td class="tbl_right f12_ar">3,130.55</td>
									<td class="tbl_right f12_ar">3,068.57</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">3,065.11</td>
									<td class="tbl_right f12_ar">3,099.56</td>
									<td class="tbl_right f12_ar">4.0250</td>
									<td class="tbl_right f12_ar">2.6515</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('BDT','20200930');">
											 BDT 
									</a></td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">13.79</td>
									<td class="tbl_right f12_ar">7.6235</td>
									<td class="tbl_right f12_ar">0.0118</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('BRL','20200930');">
											 BRL 
									</a></td>
									<td class="tbl_right f12_ar">227.54</td>
									<td class="tbl_right f12_ar">10.20</td>
									<td class="tbl_right f12_ar">189.97</td>
									<td class="tbl_right f12_ar">8.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">204.01</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">206.48</td>
									<td class="tbl_right f12_ar">2.9990</td>
									<td class="tbl_right f12_ar">0.1766</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('BND','20200930');">
											 BND 
									</a></td>
									<td class="tbl_right f12_ar">887.90</td>
									<td class="tbl_right f12_ar">4.00</td>
									<td class="tbl_right f12_ar">802.53</td>
									<td class="tbl_right f12_ar">6.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">853.75</td>
									<td class="tbl_right f12_ar">2.4250</td>
									<td class="tbl_right f12_ar">0.7303</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('SAR','20200930');">
											 SAR 
									</a></td>
									<td class="tbl_right f12_ar">331.30</td>
									<td class="tbl_right f12_ar">6.30</td>
									<td class="tbl_right f12_ar">290.17</td>
									<td class="tbl_right f12_ar">6.90</td>
									<td class="tbl_right f12_ar">314.78</td>
									<td class="tbl_right f12_ar">308.56</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">308.34</td>
									<td class="tbl_right f12_ar">311.67</td>
									<td class="tbl_right f12_ar">2.6450</td>
									<td class="tbl_right f12_ar">0.2666</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('LKR','20200930');">
											 LKR 
									</a></td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">6.31</td>
									<td class="tbl_right f12_ar">6.6250</td>
									<td class="tbl_right f12_ar">0.0054</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('SEK','20200930');">
											 SEK 
									</a></td>
									<td class="tbl_right f12_ar">132.73</td>
									<td class="tbl_right f12_ar">2.45</td>
									<td class="tbl_right f12_ar">126.39</td>
									<td class="tbl_right f12_ar">2.45</td>
									<td class="tbl_right f12_ar">130.85</td>
									<td class="tbl_right f12_ar">128.27</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">128.21</td>
									<td class="tbl_right f12_ar">129.56</td>
									<td class="tbl_right f12_ar">1.9450</td>
									<td class="tbl_right f12_ar">0.1108</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('CHF','20200930');">
											 CHF 
									</a></td>
									<td class="tbl_right f12_ar">1,292.59</td>
									<td class="tbl_right f12_ar">1.97</td>
									<td class="tbl_right f12_ar">1,242.65</td>
									<td class="tbl_right f12_ar">1.97</td>
									<td class="tbl_right f12_ar">1,280.29</td>
									<td class="tbl_right f12_ar">1,254.95</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">1,254.54</td>
									<td class="tbl_right f12_ar">1,267.62</td>
									<td class="tbl_right f12_ar">1.1654</td>
									<td class="tbl_right f12_ar">1.0844</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('AED','20200930');">
											 AED 
									</a></td>
									<td class="tbl_right f12_ar">335.76</td>
									<td class="tbl_right f12_ar">5.50</td>
									<td class="tbl_right f12_ar">296.31</td>
									<td class="tbl_right f12_ar">6.90</td>
									<td class="tbl_right f12_ar">321.44</td>
									<td class="tbl_right f12_ar">315.08</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">314.89</td>
									<td class="tbl_right f12_ar">318.26</td>
									<td class="tbl_right f12_ar">2.2550</td>
									<td class="tbl_right f12_ar">0.2722</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('DZD','20200930');">
											 DZD 
									</a></td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">9.04</td>
									<td class="tbl_right f12_ar">6.4750</td>
									<td class="tbl_right f12_ar">0.0077</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('OMR','20200930');">
											 OMR 
									</a></td>
									<td class="tbl_right f12_ar">3,310.89</td>
									<td class="tbl_right f12_ar">8.90</td>
									<td class="tbl_right f12_ar">2,857.90</td>
									<td class="tbl_right f12_ar">6.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">3,040.31</td>
									<td class="tbl_right f12_ar">4.3750</td>
									<td class="tbl_right f12_ar">2.6008</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('JOD','20200930');">
											 JOD 
									</a></td>
									<td class="tbl_right f12_ar">1,795.54</td>
									<td class="tbl_right f12_ar">8.90</td>
									<td class="tbl_right f12_ar">1,516.90</td>
									<td class="tbl_right f12_ar">8.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">1,648.80</td>
									<td class="tbl_right f12_ar">5.4910</td>
									<td class="tbl_right f12_ar">1.4104</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('ILS','20200930');">
											 ILS 
									</a></td>
									<td class="tbl_right f12_ar">372.11</td>
									<td class="tbl_right f12_ar">10.00</td>
									<td class="tbl_right f12_ar">311.23</td>
									<td class="tbl_right f12_ar">8.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">338.29</td>
									<td class="tbl_right f12_ar">2.1450</td>
									<td class="tbl_right f12_ar">0.2894</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('EGP','20200930');">
											 EGP 
									</a></td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">74.03</td>
									<td class="tbl_right f12_ar">6.4750</td>
									<td class="tbl_right f12_ar">0.0633</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('INR','20200930');">
											 INR 
									</a></td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">15.84</td>
									<td class="tbl_right f12_ar">8.2250</td>
									<td class="tbl_right f12_ar">0.0136</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('IDR','20200930');">
											 IDR (100) 
									</a></td>
									<td class="tbl_right f12_ar">8.44</td>
									<td class="tbl_right f12_ar">7.00</td>
									<td class="tbl_right f12_ar">7.11</td>
									<td class="tbl_right f12_ar">10.00</td>
									<td class="tbl_right f12_ar">7.96</td>
									<td class="tbl_right f12_ar">7.82</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">7.81</td>
									<td class="tbl_right f12_ar">7.89</td>
									<td class="tbl_right f12_ar">6.0750</td>
									<td class="tbl_right f12_ar">0.0067</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('CZK','20200930');">
											 CZK 
									</a></td>
									<td class="tbl_right f12_ar">54.67</td>
									<td class="tbl_right f12_ar">8.50</td>
									<td class="tbl_right f12_ar">45.86</td>
									<td class="tbl_right f12_ar">9.00</td>
									<td class="tbl_right f12_ar">50.94</td>
									<td class="tbl_right f12_ar">49.84</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">50.39</td>
									<td class="tbl_right f12_ar">2.3750</td>
									<td class="tbl_right f12_ar">0.0431</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('CLP','20200930');">
											 CLP 
									</a></td>
									<td class="tbl_right f12_ar">1.60</td>
									<td class="tbl_right f12_ar">8.00</td>
									<td class="tbl_right f12_ar">1.38</td>
									<td class="tbl_right f12_ar">8.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">1.49</td>
									<td class="tbl_right f12_ar">1.8770</td>
									<td class="tbl_right f12_ar">0.0013</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('KZT','20200930');">
											 KZT 
									</a></td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">2.72</td>
									<td class="tbl_right f12_ar">13.4750</td>
									<td class="tbl_right f12_ar">0.0023</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('QAR','20200930');">
											 QAR 
									</a></td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">321.07</td>
									<td class="tbl_right f12_ar">2.2250</td>
									<td class="tbl_right f12_ar">0.2747</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('KES','20200930');">
											 KES 
									</a></td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">10.78</td>
									<td class="tbl_right f12_ar">11.4750</td>
									<td class="tbl_right f12_ar">0.0092</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('COP','20200930');">
											 COP 
									</a></td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.30</td>
									<td class="tbl_right f12_ar">0.0000</td>
									<td class="tbl_right f12_ar">0.0003</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('KWD','20200930');">
											 KWD 
									</a></td>
									<td class="tbl_right f12_ar">4,062.74</td>
									<td class="tbl_right f12_ar">6.50</td>
									<td class="tbl_right f12_ar">3,509.60</td>
									<td class="tbl_right f12_ar">8.00</td>
									<td class="tbl_right f12_ar">3,852.92</td>
									<td class="tbl_right f12_ar">3,776.64</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">3,773.23</td>
									<td class="tbl_right f12_ar">3,814.78</td>
									<td class="tbl_right f12_ar">3.2250</td>
									<td class="tbl_right f12_ar">3.2633</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('TZS','20200930');">
											 TZS 
									</a></td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.50</td>
									<td class="tbl_right f12_ar">8.2250</td>
									<td class="tbl_right f12_ar">0.0004</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('TRY','20200930');">
											 TRY 
									</a></td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">151.74</td>
									<td class="tbl_right f12_ar">148.44</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">150.09</td>
									<td class="tbl_right f12_ar">13.0750</td>
									<td class="tbl_right f12_ar">0.1284</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('PKR','20200930');">
											 PKR 
									</a></td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">7.05</td>
									<td class="tbl_right f12_ar">15.4750</td>
									<td class="tbl_right f12_ar">0.0060</td>

								</tr>

								<tr>


									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('PLN','20200930');">
											 PLN 
									</a></td>
									<td class="tbl_right f12_ar">324.28</td>
									<td class="tbl_right f12_ar">8.00</td>
									<td class="tbl_right f12_ar">276.24</td>
									<td class="tbl_right f12_ar">8.00</td>
									<td class="tbl_right f12_ar">303.56</td>
									<td class="tbl_right f12_ar">296.96</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">300.26</td>
									<td class="tbl_right f12_ar">2.3850</td>
									<td class="tbl_right f12_ar">0.2569</td>

								</tr>

								<tr class="cell-bottom">
									<td scope="row"><a href="#//HanaBank"
										title="View Daily Fluctuation History"
										onclick="pbk.foreign.rate.pbld.prs.goFluctuation('HUF','20200930');">
											 HUF 
									</a></td>
									<td class="tbl_right f12_ar">4.08</td>
									<td class="tbl_right f12_ar">9.30</td>
									<td class="tbl_right f12_ar">3.45</td>
									<td class="tbl_right f12_ar">8.00</td>
									<td class="tbl_right f12_ar">3.78</td>
									<td class="tbl_right f12_ar">3.70</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">0.00</td>
									<td class="tbl_right f12_ar">3.74</td>
									<td class="tbl_right f12_ar">2.7850</td>
									<td class="tbl_right f12_ar">0.0032</td>
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