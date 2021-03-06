
function set_hosts(selected)
{
  $.ajax({
        url: script_root + '/hosts/',
        type: 'POST',
        data:  JSON.stringify({'selected': selected} ),
        cache: false,
        contentType: "application/json;charset=UTF-8",
    }).done(function(data) {
        var res = JSON.parse(data);
        $('#host_selector').html(res.html);
    });
}


function set_ip_click_handler() {
    $(".ip_addr").unbind("click");
    $(".ip_addr").click(function(event) {
        $("#dns_popup").modal('show');
        $("#dns_popup_content").text("Loading....");
        $.ajax({
            url: script_root +"/reverse_dns/"+ encodeURIComponent($(this).attr('data-content')) ,
            type: "GET"
        }).done(function(data) {
            $("#dns_popup_content").html(data);
            $("#dns_popup").modal("handleUpdate")
        });
    })

}

function get_period()
{
    var to = null;
    var from = null;
    var period = 'today'
    if ($("#daily").is(":checked")) {period = 'today';}
    else if ($("#hourly").is(":checked")) {period = 'hour';}
    else if ($("#24hour").is(":checked")) {period = '24hour';}
    else if ($("#yesterday").is(":checked")) {period = 'yesterday';}
    else if ($("#weekly").is(":checked")) {period = 'week';}
    else if ($("#monthly").is(":checked")) {period = 'month';}
    else if ($("#custom").is(":checked")) {
        period = 'custom';
        from = $("#from_date").val();
        to = $("#to_date").val();
    }
    return {period, from, to}
}


