package oauth2

import (
	"github.com/jesposito/pocketbase-ext-oauth2-mt/consts"
	"github.com/pocketbase/pocketbase/core"
)

type JTIModel struct {
	core.BaseRecordProxy
}

func NewJTIModel(app core.App) *JTIModel {
	m := &JTIModel{}
	c, err := app.FindCachedCollectionByNameOrId(consts.JTICollectionName)
	if err != nil {
		c = core.NewBaseCollection("@__invalid__")
	}
	m.Record = core.NewRecord(c)
	return m
}
