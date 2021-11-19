
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
