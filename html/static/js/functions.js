
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