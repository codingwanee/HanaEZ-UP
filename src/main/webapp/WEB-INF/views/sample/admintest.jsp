<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<head>
<jsp:include page="/WEB-INF/views/admin/include/head.jsp" />
</head>
</head>
<body>
	<!-- ======= Footer ======= -->
	<jsp:include page="/WEB-INF/views/admin/include/aside.jsp" />
	<!-- End Footer -->

	<div class="container">
		<div class="row">
			<div class="col-md-6">
				<!-- begin panel -->
				<div class="panel panel-inverse"
					data-sortable-id="form-validation-2">
					<div class="panel-heading">
							<a href="javascript:;"
								class="btn btn-xs btn-icon btn-circle btn-default"
								data-click="panel-expand"><i class="fa fa-expand"></i></a> <a
								href="javascript:;"
								class="btn btn-xs btn-icon btn-circle btn-success"
								data-click="panel-reload"><i class="fa fa-repeat"></i></a> <a
								href="javascript:;"
								class="btn btn-xs btn-icon btn-circle btn-warning"
								data-click="panel-collapse"><i class="fa fa-minus"></i></a> <a
								href="javascript:;"
								class="btn btn-xs btn-icon btn-circle btn-danger"
								data-click="panel-remove"><i class="fa fa-times"></i></a>
						</div>
						<h4 class="panel-title">Extra Validation Field</h4>
					</div>
					<div class="panel-body panel-form">
						<form class="form-horizontal form-bordered"
							data-parsley-validate="true">
							<div class="form-group">
								<label class="control-label col-md-4 col-sm-4">AlphaNum*
									:</label>
								<div class="col-md-6 col-sm-6">
									<input class="form-control" type="text" id="alphanum"
										name="alphanum" data-type="alphanum"
										placeholder="Alphanumeric String."
										data-parsley-required="true" />
								</div>
							</div>
							<div class="form-group">
								<label class="control-label col-md-4 col-sm-4">Date ISO*
									:</label>
								<div class="col-md-6 col-sm-6">
									<input class="form-control" type="text" id="data-dateIso"
										placeholder="YYYY-MM-DD" data-parsley-required="true" />
								</div>
							</div>
							<div class="form-group">
								<label class="control-label col-md-4 col-sm-4">Required
									Select Box :</label>
								<div class="col-md-6 col-sm-6">
									<select class="form-control" id="select-required"
										name="selectBox" data-parsley-required="true">
										<option value="">Please choose</option>
										<option value="foo">Foo</option>
										<option value="bar">Bar</option>
									</select>
								</div>
							</div>
							<div class="form-group">
								<label class="control-label col-md-4 col-sm-4">Required
									Radio Button :</label>
								<div class="col-md-6 col-sm-6">
									<div class="radio">
										<label> <input type="radio" name="radiorequired"
											value="foo" id="radio-required" data-parsley-required="true" />
											Radio Button 1
										</label>
									</div>
									<div class="radio">
										<label> <input type="radio" name="radiorequired"
											id="radio-required2" value="bar" /> Radio Button 2
										</label>
									</div>
								</div>
							</div>
							<div class="form-group">
								<label class="control-label col-md-4 col-sm-4">Check at
									least 2 checkboxes :</label>
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
							<div class="form-group">
								<label class="control-label col-md-4 col-sm-4">Regular
									Expression :</label>
								<div class="col-md-6 col-sm-6">
									<input class="form-control parsley-validated" type="text"
										id="data-regexp" data-parsley-pattern="#[A-Fa-f0-9]{6}"
										placeholder="hexa color code" data-required="true" />
								</div>
							</div>
							<div class="form-group">
								<label class="control-label col-md-4 col-sm-4"></label>
								<div class="col-md-6 col-sm-6">
									<button type="submit" class="btn btn-danger">Validate</button>
								</div>
							</div>
						</form>
					</div>
				</div>
			</div>
		</div>

	<!-- end panel -->



	<!-- ======= Footer ======= -->
	<jsp:include page="/WEB-INF/views/admin/include/common-js.jsp" />
	<!-- End Footer -->
</body>
</html>