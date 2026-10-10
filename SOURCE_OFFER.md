# Corresponding source Good Bear 1.0.0

Этот репозиторий содержит только исходные изменения Good Bear: упорядоченную
серию patches, overlay и закреплённые сведения о Firefox. Внутренние планы,
playbooks, журналы сборок, облачная инфраструктура, учётные данные и build
outputs в corresponding source не публикуются.

Good Bear основан на Firefox 156.0. Получите точный исходный архив по адресу
`https://archive.mozilla.org/pub/firefox/releases/156.0/source/firefox-156.0.source.tar.xz` и проверьте SHA-256:

```text
1f2768c043510009abaa3f078123664e106d3ab9dfce75d1819ad96b2145aab9  firefox-156.0.source.tar.xz
```

Распакуйте архив, примените patches из `patches/series` строго по порядку с
`patch -p1`, затем скопируйте содержимое `overlay/` поверх полученного дерева.
Русская локализация и словарь находятся в overlay. Сертификаты Russian PKI
получаются только из закреплённых официальных источников во время сборки; их
байты и никакие секреты в репозитории не хранятся.

Исходный код Good Bear распространяется по Mozilla Public License 2.0. Полные
уведомления Mozilla и сторонних компонентов находятся в исходном архиве
Firefox и в установленном приложении.
