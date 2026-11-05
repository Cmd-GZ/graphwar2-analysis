extends Node

var frames := 0
var dumped := false

func _dump(n: Node, depth: int) -> void:
	if depth > 2:
		return
	print("TREE ", "  ".repeat(depth), n.name, " [", n.get_class(), "]")
	for c in n.get_children():
		_dump(c, depth + 1)

func _ready() -> void:
	print("PROBE_READY")

func _process(_dt: float) -> void:
	frames += 1
	if frames == 60:
		print("PROBE_F60 current=", get_tree().current_scene)
		_dump(get_tree().root, 0)
		dumped = true
	if frames > 90 and dumped:
		get_tree().quit()
